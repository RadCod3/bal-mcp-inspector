import ballerina/crypto;
import ballerina/http;
import ballerina/lang.array;
import ballerina/lang.regexp;
import ballerina/mcp;
import ballerina/time;
import ballerina/url;
import ballerina/uuid;

// Enterprise-managed authorization (ID-JAG) runs in three legs:
//   1. OpenID Connect sign-in at the Identity Provider, which yields the user's ID token. The playground
//      performs it here, reusing the OAuth callback broker for the redirect.
//   2. Token exchange of the ID token for an ID-JAG at the Identity Provider (mcp:exchangeIdTokenForIdJag).
//   3. The jwt-bearer request at the resource authorization server, made by the MCP client.
// Every Identity Provider request is recorded against the "identity_provider" target.

const IDENTITY_PROVIDER_TARGET = "identity_provider";
const REDACTED = "[REDACTED]";
// A token the playground decoded for the log. Not part of any HTTP exchange.
const TOKEN_DECODED_EVENT = "playground.token_decoded";
const PKCE_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
// An ID token is renewed this long before it expires.
const int ID_TOKEN_EXPIRY_MARGIN_SECONDS = 30;

type IdToken record {|
    string token;
    // Seconds since the epoch, or () when the token carries no `exp`
    int? expiresAt;
|};

// The ID token of each enterprise-managed connection, reused until it expires.
isolated class IdTokenStore {
    private map<IdToken> tokens = {};

    isolated function valid(string connectionId) returns string? {
        lock {
            IdToken? idToken = self.tokens[connectionId];
            if idToken is () {
                return ();
            }
            int? expiresAt = idToken.expiresAt;
            if expiresAt is int && time:utcNow()[0] >= expiresAt - ID_TOKEN_EXPIRY_MARGIN_SECONDS {
                return ();
            }
            return idToken.token;
        }
    }

    isolated function set(string connectionId, IdToken idToken) {
        lock {
            self.tokens[connectionId] = idToken.clone();
        }
    }

    isolated function remove(string connectionId) {
        lock {
            if self.tokens.hasKey(connectionId) {
                _ = self.tokens.remove(connectionId);
            }
        }
    }
}

final IdTokenStore idTokenStore = new;

// The playground's assertionProvider: signs the user in if needed (leg 1), then obtains an ID-JAG for the
// resource authorization server the MCP client discovered (leg 2).
isolated function provideIdJag(string connectionId, readonly & IdentityProviderSettings settings,
        mcp:IdentityAssertionContext context) returns string|error {
    string idToken = check currentIdToken(connectionId, settings);
    mcp:IdentityProviderConfig identityProvider = {issuer: settings.issuer, clientId: settings.clientId};
    ClientSecretAuthentication? clientAuth = settings?.clientAuth;
    if clientAuth is ClientSecretAuthentication {
        identityProvider.clientAuth = {clientSecret: clientAuth.clientSecret, authMethod: clientAuth.authMethod};
    }
    string idJag = check mcp:exchangeIdTokenForIdJag(idToken, context, identityProvider,
        new InspectorClientObserver(connectionId));
    recordDecodedIdJag(connectionId, idJag);
    return idJag;
}

// The observer records the token exchange with the ID-JAG redacted. This adds its header and payload as a
// separate event, which the request log shows beside that exchange. The signature is dropped, so the
// recorded values can't be presented as a credential.
isolated function recordDecodedIdJag(string connectionId, string idJag) {
    map<json>|error header = jwtPart(idJag, 0);
    map<json>|error payload = jwtPart(idJag, 1);
    string? eventBody = header is map<json> && payload is map<json>
        ? {token: "ID-JAG", header, payload}.toJsonString() : ();
    eventStore.append(connectionId, {
        sequence: 0,
        timestamp: "",
        connectionId,
        eventType: TOKEN_DECODED_EVENT,
        eventTarget: IDENTITY_PROVIDER_TARGET,
        eventBody,
        eventMessage: eventBody is string ? "ID-JAG decoded by the playground; signature removed"
            : "The ID-JAG is not a compact JWT, so it can't be decoded"
    });
}

isolated function currentIdToken(string connectionId, readonly & IdentityProviderSettings settings)
        returns string|error {
    string? cached = idTokenStore.valid(connectionId);
    if cached is string {
        return cached;
    }
    IdToken idToken = check signInAtIdentityProvider(connectionId, settings);
    idTokenStore.set(connectionId, idToken);
    return idToken.token;
}

type OpenIdEndpoints record {|
    string authorizationEndpoint;
    string tokenEndpoint;
|};

// Leg 1: OpenID Connect authorization code sign-in with PKCE.
isolated function signInAtIdentityProvider(string connectionId, readonly & IdentityProviderSettings settings)
        returns IdToken|error {
    OpenIdEndpoints endpoints = check discoverOpenIdEndpoints(connectionId, settings.issuer);
    string verifier = createCodeVerifier();
    string nonce = uuid:createType4AsString();
    string authorizationUrl = endpoints.authorizationEndpoint +
        (endpoints.authorizationEndpoint.includes("?") ? "&" : "?") + check encodeForm({
            "response_type": "code",
            "client_id": settings.clientId,
            "redirect_uri": settings.redirectUri,
            "scope": string:'join(" ", ...settings.loginScopes),
            "state": uuid:createType4AsString(),
            "nonce": nonce,
            "code_challenge": toBase64Url(crypto:hashSha256(verifier.toBytes())),
            "code_challenge_method": "S256"
        });
    // Registers the state with the callback broker and asks the user to open the URL.
    check redirectHandler(connectionId, authorizationUrl);
    mcp:AuthorizationCallbackParams callbackParams = check callbackHandler(connectionId);

    string? callbackError = callbackParams?.'error;
    if callbackError is string {
        return error(string `Identity Provider sign-in failed with '${callbackError}': ` +
            string `${callbackParams?.errorDescription ?: ""}`);
    }
    string? iss = callbackParams?.iss;
    if iss is string && iss != settings.issuer {
        return error(string `The sign-in response names issuer '${iss}', not '${settings.issuer}'.`);
    }
    string? code = callbackParams?.code;
    if code is () {
        return error("The Identity Provider sign-in response does not contain an authorization code.");
    }
    connectionRegistry.setState(connectionId, "connecting");
    appendLifecycleEvent(connectionId, "connection.connecting", "connecting",
        eventMessage = "Signed in at the Identity Provider");

    map<json> tokens = check postTokenForm(connectionId, endpoints.tokenEndpoint, {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.redirectUri,
        "code_verifier": verifier
    }, settings);
    json idToken = tokens["id_token"];
    if idToken !is string {
        return error("The Identity Provider returned no ID token. Include 'openid' in the sign-in scopes.");
    }
    map<json> claims = check jwtClaims(idToken);
    if claims["nonce"] != nonce {
        return error("The ID token's nonce does not match the sign-in request.");
    }
    json expiry = claims["exp"];
    int? expiresAt = expiry is int ? expiry : ();
    appendIdentityProviderEvent(connectionId, "oauth.token_acquired", endpoints.tokenEndpoint,
        eventMessage = "ID token acquired from the Identity Provider" +
            (expiresAt is int ? string ` (expires ${time:utcToString([expiresAt, 0])})` : ""));
    return {token: idToken, expiresAt};
}

// Reads the Identity Provider's OpenID Connect discovery document, falling back to RFC 8414 metadata.
isolated function discoverOpenIdEndpoints(string connectionId, string issuer) returns OpenIdEndpoints|error {
    string base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
    error? lastError = ();
    foreach string path in ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"] {
        json|error metadata = getJson(connectionId, base + path);
        if metadata is error {
            lastError = metadata;
            continue;
        }
        if metadata !is map<json> || metadata["issuer"] != issuer {
            return error(string `The metadata at '${base + path}' does not declare issuer '${issuer}'.`);
        }
        json authorizationEndpoint = metadata["authorization_endpoint"];
        json tokenEndpoint = metadata["token_endpoint"];
        if authorizationEndpoint !is string || tokenEndpoint !is string {
            return error(string `The metadata at '${base + path}' lacks an authorization or token endpoint.`);
        }
        return {authorizationEndpoint, tokenEndpoint};
    }
    return error(string `Failed to discover the Identity Provider metadata for '${issuer}'.`, lastError);
}

isolated function getJson(string connectionId, string targetUrl) returns json|error {
    appendIdentityProviderEvent(connectionId, "http.request", targetUrl, "GET");
    http:Client metadataClient = check new (targetUrl);
    http:Response|error response = metadataClient->get("");
    if response is error {
        appendIdentityProviderEvent(connectionId, "client.error", targetUrl, "GET", eventMessage = response.message());
        return response;
    }
    string body = check response.getTextPayload();
    appendIdentityProviderEvent(connectionId, "http.response", targetUrl, "GET", response.statusCode,
        responseHeaders(response));
    appendIdentityProviderEvent(connectionId, "http.body", targetUrl, "GET", response.statusCode,
        eventBody = body, eventMessage = "Identity Provider metadata");
    if response.statusCode != http:STATUS_OK {
        return error(string `'${targetUrl}' returned status ${response.statusCode}.`);
    }
    return body.fromJsonString();
}

// Posts a token request with the Identity Provider client's authentication. Its events match the MCP
// client's: the form body with credentials redacted, and the response with its tokens redacted.
isolated function postTokenForm(string connectionId, string tokenEndpoint, map<string> form,
        readonly & IdentityProviderSettings settings) returns map<json>|error {
    map<string> params = form.clone();
    map<string> headers = {"Accept": "application/json"};
    ClientSecretAuthentication? clientAuth = settings?.clientAuth;
    if clientAuth is () {
        params["client_id"] = settings.clientId;
    } else if clientAuth.authMethod == mcp:CLIENT_SECRET_POST {
        params["client_id"] = settings.clientId;
        params["client_secret"] = clientAuth.clientSecret;
    } else {
        string credentials = (check encodeValue(settings.clientId)) + ":" + (check encodeValue(clientAuth.clientSecret));
        headers["Authorization"] = "Basic " + credentials.toBytes().toBase64();
    }

    // The redaction marker is left unencoded so it stays readable.
    string[] recordedPairs = [];
    foreach [string, string] [name, value] in params.entries() {
        boolean secret = name == "code" || name == "code_verifier" || name == "client_secret";
        recordedPairs.push(name + "=" + (secret ? REDACTED : check encodeValue(value)));
    }
    // The content type goes to `post` separately, so it is added to the recorded headers here.
    map<string> recordedHeaders = headers.clone();
    recordedHeaders["Content-Type"] = "application/x-www-form-urlencoded";
    appendIdentityProviderEvent(connectionId, "http.request", tokenEndpoint, "POST",
        eventHeaders = redactedHeaders(recordedHeaders), eventBody = string:'join("&", ...recordedPairs),
        eventMessage = "OpenID Connect token request");
    http:Client tokenClient = check new (tokenEndpoint);
    http:Response|error response = tokenClient->post("", check encodeForm(params), headers,
        "application/x-www-form-urlencoded");
    if response is error {
        appendIdentityProviderEvent(connectionId, "client.error", tokenEndpoint, "POST",
            eventMessage = response.message());
        return response;
    }
    appendIdentityProviderEvent(connectionId, "http.response", tokenEndpoint, "POST", response.statusCode,
        responseHeaders(response));
    string|error responseText = response.getTextPayload();
    json|error payload = responseText is string ? responseText.fromJsonString() : responseText;
    string? recordedBody = payload is map<json> ? redactedTokenResponse(payload).toJsonString()
        // A body that isn't a JSON object is recorded only for an error, which carries no tokens.
        : response.statusCode != http:STATUS_OK && responseText is string && responseText != "" ? responseText : ();
    if recordedBody is string {
        appendIdentityProviderEvent(connectionId, "http.body", tokenEndpoint, "POST", response.statusCode,
            eventBody = recordedBody, eventMessage = "OpenID Connect token response, tokens redacted");
    }
    if response.statusCode != http:STATUS_OK {
        string reason = payload is map<json> ? (payload["error"] ?: "").toString() : "";
        return error(string `The Identity Provider token endpoint returned ${response.statusCode}` +
            (reason == "" ? "." : string ` ('${reason}').`));
    }
    return (check payload).ensureType();
}

isolated function appendIdentityProviderEvent(string connectionId, string eventType, string eventUrl,
        string? httpMethod = (), int? statusCode = (), map<string|string[]> eventHeaders = {},
        string? eventBody = (), string? eventMessage = ()) {
    eventStore.append(connectionId, {
        sequence: 0,
        timestamp: "",
        connectionId,
        eventType,
        eventTarget: IDENTITY_PROVIDER_TARGET,
        eventUrl,
        httpMethod,
        statusCode,
        eventHeaders,
        eventBody,
        eventMessage
    });
}

isolated function responseHeaders(http:Response response) returns map<string|string[]> {
    map<string|string[]> headers = {};
    foreach string name in response.getHeaderNames() {
        string[]|error values = response.getHeaders(name);
        if values is string[] {
            headers[name] = values;
        }
    }
    return redactedHeaders(headers);
}

isolated function redactedTokenResponse(map<json> tokenResponse) returns map<json> {
    map<json> redacted = {};
    foreach [string, json] [name, value] in tokenResponse.entries() {
        string lowerName = name.toLowerAscii();
        redacted[name] = lowerName == "id_token" || lowerName == "access_token" || lowerName == "refresh_token"
            ? REDACTED : value;
    }
    return redacted;
}

isolated function redactedHeaders(map<string|string[]> headers) returns map<string|string[]> {
    map<string|string[]> redacted = {};
    foreach [string, string|string[]] [name, value] in headers.entries() {
        string lowerName = name.toLowerAscii();
        redacted[name] = lowerName == "authorization" || lowerName == "cookie" || lowerName == "set-cookie"
            ? REDACTED : value;
    }
    return redacted;
}

isolated function encodeForm(map<string> params) returns string|error {
    string[] pairs = [];
    foreach [string, string] [name, value] in params.entries() {
        pairs.push(name + "=" + check encodeValue(value));
    }
    return string:'join("&", ...pairs);
}

isolated function encodeValue(string value) returns string|error =>
    regexp:replaceAll(re `%20`, check url:encode(value, "UTF-8"), "+");

// A 43-character PKCE verifier (RFC 7636) derived from two random UUIDs.
isolated function createCodeVerifier() returns string =>
    toBase64Url(crypto:hashSha256((uuid:createType4AsString() + uuid:createType4AsString()).toBytes()));

isolated function toBase64Url(byte[] bytes) returns string {
    string encoded = array:toBase64(bytes);
    encoded = regexp:replaceAll(re `\+`, encoded, "-");
    encoded = regexp:replaceAll(re `/`, encoded, "_");
    return regexp:replaceAll(re `=+$`, encoded, "");
}

// Reads a JWT's claims without verifying it; used only to check the nonce and expiry of an ID token the
// inspector received directly from the Identity Provider's token endpoint.
isolated function jwtClaims(string jwt) returns map<json>|error {
    map<json>|error claims = jwtPart(jwt, 1);
    return claims is error ? error("The ID token is not a JWT.", claims) : claims;
}

// Decodes the header (0) or payload (1) of a compact JWT, without verifying it.
isolated function jwtPart(string jwt, int index) returns map<json>|error {
    string[] parts = re `\.`.split(jwt);
    if parts.length() != 3 {
        return error("The token is not a compact JWT.");
    }
    string part = regexp:replaceAll(re `_`, regexp:replaceAll(re `-`, parts[index], "+"), "/");
    while part.length() % 4 != 0 {
        part += "=";
    }
    json decoded = check (check string:fromBytes(check array:fromBase64(part))).fromJsonString();
    return decoded.ensureType();
}
