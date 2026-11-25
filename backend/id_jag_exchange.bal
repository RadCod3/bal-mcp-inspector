import ballerina/http;
import ballerina/mcp;

// Leg 2 of enterprise-managed authorization: the RFC 8693 exchange of the user's ID token for an ID-JAG.
//
// This mirrors mcp:exchangeIdTokenForIdJag and the module-internal functions it relies on, with one
// difference: an OpenID Provider whose `grant_types_supported` omits the token exchange grant is still asked
// for the ID-JAG. Some providers support token exchange without advertising it, and neither the MCP
// authorization specification nor the ID-JAG profile requires the grant to be advertised. Discovery, the
// other capability checks, the request, the response validation, and the observer events are the helper's,
// so the transcript records this leg as before, with credentials and tokens redacted.

const GRANT_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
const TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
const TOKEN_TYPE_ID_JAG = "urn:ietf:params:oauth:token-type:id-jag";
const CLIENT_AUTH_NONE = "none";
const OAUTH_AUTHORIZATION_SERVER_METADATA_PATH = "/.well-known/oauth-authorization-server";
const OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";

// OpenID Provider metadata used for token exchange. Optional capabilities are checked when advertised.
type IdentityProviderMetadata record {
    string issuer;
    string token_endpoint;
    string[] grant_types_supported?;
    string[] token_endpoint_auth_methods_supported?;
    string[] token_endpoint_auth_signing_alg_values_supported?;
    string[] identity_chaining_requested_token_types_supported?;
    record {string token_endpoint?;} mtls_endpoint_aliases?;
};

// RFC 8693 token exchange response (section 2.2.1).
type TokenExchangeResponse record {
    string access_token;
    string issued_token_type;
    string token_type;
    int expires_in?;
    string scope?;
};

// The playground's Identity Provider clients authenticate with a client secret, or not at all.
type IdentityProviderClientAuth mcp:ClientSecretConfig;

// A validated and discovered Identity Provider ready for RFC 8693 token exchanges.
type IdentityProvider record {|
    string clientId;
    IdentityProviderClientAuth? clientAuth;
    IdentityProviderMetadata metadata;
    mcp:IdentityProviderConfig httpConfig;
|};

type TokenExchangeRequest record {|
    string subjectToken;
    string subjectTokenType;
    string requestedTokenType;
    string audience?;
    string 'resource?;
    string[] scopes = [];
|};

type UrlParts record {|
    string scheme;
    string origin;
    string path;
    string query;
|};

// Exchanges an ID token for a fresh ID-JAG at the OpenID Provider. Same as mcp:exchangeIdTokenForIdJag,
// except that the token exchange grant need not be listed in `grant_types_supported`.
isolated function exchangeIdTokenForIdJag(string idToken, mcp:IdentityAssertionContext context,
        mcp:IdentityProviderConfig config, mcp:ClientObserver? observer = ()) returns string|error {
    if idToken.trim() == "" {
        return error("'idToken' must not be empty.");
    }
    IdentityProvider idp = check prepareIdentityProvider(config, observer);
    check validateIdJagIssuanceSupported(idp.metadata);
    TokenExchangeResponse response = check requestTokenExchange(idp, {
        subjectToken: idToken,
        subjectTokenType: TOKEN_TYPE_ID_TOKEN,
        requestedTokenType: TOKEN_TYPE_ID_JAG,
        audience: context.audience,
        'resource: context.'resource,
        scopes: context.scopes
    }, observer);
    notifyObserver(observer, {
        eventType: mcp:TOKEN_ACQUIRED,
        eventTarget: mcp:IDENTITY_PROVIDER,
        eventUrl: selectTokenEndpoint(idp.metadata),
        eventMessage: "ID-JAG issued by the Identity Provider"
    });
    return response.access_token;
}

// Prepares an Identity Provider and checks the capabilities shared by every token exchange.
isolated function prepareIdentityProvider(mcp:IdentityProviderConfig config, mcp:ClientObserver? observer)
        returns IdentityProvider|error {
    if config.clientId.trim() == "" {
        return error("'clientId' must not be empty.");
    }
    check validateHttpsUrl(config.issuer, "issuer");
    mcp:ClientAuth? configuredAuth = config?.clientAuth;
    if configuredAuth is mcp:PrivateKeyJwtConfig|mcp:MutualTlsConfig {
        return error("The playground's token exchange supports 'client_secret_post', 'client_secret_basic', " +
            "and public Identity Provider clients.");
    }
    IdentityProviderClientAuth? clientAuth = configuredAuth;
    if clientAuth is IdentityProviderClientAuth && clientAuth.clientSecret == "" {
        return error("'clientSecret' must not be empty.");
    }
    IdentityProviderMetadata metadata = check discoverIdentityProviderMetadata(config.issuer, config, observer);
    check validateTokenExchangeSupported(clientAuth, metadata);
    return {clientId: config.clientId, clientAuth, metadata, httpConfig: config};
}

// The helper also rejects a provider whose `grant_types_supported` omits the token exchange grant. That
// check is skipped: advertising the grant is optional, and omission does not mean it is unsupported.
isolated function validateTokenExchangeSupported(IdentityProviderClientAuth? clientAuth,
        IdentityProviderMetadata metadata) returns error? {
    if metadata.token_endpoint_auth_methods_supported is () {
        return;
    }
    return validateClientAuthSupported(clientAuth, metadata);
}

isolated function validateClientAuthSupported(IdentityProviderClientAuth? clientAuth,
        IdentityProviderMetadata metadata) returns error? {
    // RFC 8414 section 2 defaults an omitted token_endpoint_auth_methods_supported to client_secret_basic.
    string[] supported = metadata.token_endpoint_auth_methods_supported ?: [mcp:CLIENT_SECRET_BASIC];
    string configured = clientAuth is IdentityProviderClientAuth ? clientAuth.authMethod : CLIENT_AUTH_NONE;
    if supported.indexOf(configured) is () {
        return error(string `Authorization server '${metadata.issuer}' does not ` +
            string `support the '${configured}' client authentication method. It supports: ` +
            string `${string:'join(", ", ...supported)}.`);
    }
}

// Checks ID-JAG support when the Identity Provider advertises identity-chaining token types.
isolated function validateIdJagIssuanceSupported(IdentityProviderMetadata metadata) returns error? {
    string[]? advertisedTokenTypes = metadata.identity_chaining_requested_token_types_supported;
    if advertisedTokenTypes is string[] && advertisedTokenTypes.indexOf(TOKEN_TYPE_ID_JAG) is () {
        return error(string `OpenID Provider '${metadata.issuer}' advertises ` +
            string `'identity_chaining_requested_token_types_supported' but does not include ID-JAG.`);
    }
}

// Performs the RFC 8693 exchange and validates the returned token type. Its events are reported against
// the Identity Provider.
isolated function requestTokenExchange(IdentityProvider idp, TokenExchangeRequest request,
        mcp:ClientObserver? observer) returns TokenExchangeResponse|error {
    string tokenEndpoint = selectTokenEndpoint(idp.metadata);
    json payload = check postTokenRequest(idp, buildTokenExchangeForm(request), observer);
    return parseTokenExchangeResponse(payload, request.requestedTokenType, tokenEndpoint);
}

isolated function buildTokenExchangeForm(TokenExchangeRequest request) returns map<string> {
    map<string> form = {
        "grant_type": GRANT_TOKEN_EXCHANGE,
        "requested_token_type": request.requestedTokenType,
        "subject_token": request.subjectToken,
        "subject_token_type": request.subjectTokenType
    };
    string? audience = request?.audience;
    if audience is string {
        form["audience"] = audience;
    }
    string? targetResource = request?.'resource;
    if targetResource is string {
        form["resource"] = targetResource;
    }
    if request.scopes.length() > 0 {
        form["scope"] = string:'join(" ", ...request.scopes);
    }
    return form;
}

// These exchanges issue non-access tokens, so `token_type` must be `N_A`.
isolated function parseTokenExchangeResponse(json payload, string requestedTokenType, string tokenEndpoint)
        returns TokenExchangeResponse|error {
    TokenExchangeResponse|error response = payload.cloneWithType();
    if response is error {
        return error(string `Response from OpenID Provider token endpoint ` +
            string `'${tokenEndpoint}' is not a valid token exchange response.`, response);
    }
    if response.access_token.trim() == "" {
        return error(string `Response from OpenID Provider token endpoint ` +
            string `'${tokenEndpoint}' contains an empty token.`);
    }
    if response.issued_token_type != requestedTokenType {
        return error(string `Response from OpenID Provider token endpoint ` +
            string `'${tokenEndpoint}' contains issued token type '${response.issued_token_type}', ` +
            string `but '${requestedTokenType}' was requested.`);
    }
    if !response.token_type.equalsIgnoreCaseAscii("N_A") {
        return error(string `Response from OpenID Provider token endpoint ` +
            string `'${tokenEndpoint}' contains unexpected token type '${response.token_type}'.`);
    }
    int? lifetime = response?.expires_in;
    if lifetime is int && lifetime <= 0 {
        return error(string `Response from OpenID Provider token endpoint ` +
            string `'${tokenEndpoint}' contains a non-positive 'expires_in' value.`);
    }
    return response;
}

// The helper uses the `mtls_endpoint_aliases` token endpoint only for mutual TLS, which the playground's
// Identity Provider clients don't use.
isolated function selectTokenEndpoint(IdentityProviderMetadata metadata) returns string =>
    metadata.token_endpoint;

// Posts an authenticated token request and returns its successful JSON body.
isolated function postTokenRequest(IdentityProvider idp, map<string> form, mcp:ClientObserver? observer)
        returns json|error {
    string tokenEndpoint = selectTokenEndpoint(idp.metadata);
    map<string> params = form.clone();
    map<string|string[]> headers = {
        "content-type": "application/x-www-form-urlencoded",
        "accept": "application/json"
    };
    check applyClientAuthentication(idp.clientAuth, idp.clientId, params, headers);

    string body = check encodeForm(params);
    [string, string] [origin, path] = check splitUrl(tokenEndpoint);
    http:Client tokenClient = check createAuthClient(origin, idp.httpConfig);
    notifyObserver(observer, {
        eventType: mcp:HTTP_REQUEST,
        eventTarget: mcp:IDENTITY_PROVIDER,
        eventUrl: tokenEndpoint,
        httpMethod: "POST",
        eventHeaders: sanitizedEventHeaders(headers),
        eventBody: check sanitizedTokenRequestBody(params),
        eventMessage: "OAuth token request"
    });
    http:Response|error response = tokenClient->post(path, body, headers);
    if response is error {
        notifyObserver(observer, {
            eventType: mcp:CLIENT_ERROR,
            eventTarget: mcp:IDENTITY_PROVIDER,
            eventUrl: tokenEndpoint,
            httpMethod: "POST",
            eventMessage: response.message()
        });
        return error(string `Request to token endpoint '${tokenEndpoint}' failed: ${response.message()}`,
            response);
    }
    notifyObserver(observer, {
        eventType: mcp:HTTP_RESPONSE,
        eventTarget: mcp:IDENTITY_PROVIDER,
        eventUrl: tokenEndpoint,
        httpMethod: "POST",
        statusCode: response.statusCode,
        eventHeaders: sanitizedResponseHeaders(response)
    });
    string|error responseText = response.getTextPayload();
    json|error payload = responseText is string ? responseText.fromJsonString() : responseText;
    string? responseBody = tokenResponseEventBody(payload, responseText, response.statusCode);
    if responseBody is string {
        notifyObserver(observer, {
            eventType: mcp:HTTP_BODY,
            eventTarget: mcp:IDENTITY_PROVIDER,
            eventUrl: tokenEndpoint,
            httpMethod: "POST",
            statusCode: response.statusCode,
            eventBody: responseBody,
            eventMessage: "OAuth token response, tokens redacted"
        });
    }
    if response.statusCode != http:STATUS_OK {
        return tokenEndpointError(tokenEndpoint, response.statusCode, payload);
    }
    if payload is error {
        return error(string `Response from token endpoint '${tokenEndpoint}' is not valid JSON.`, payload);
    }
    return payload;
}

isolated function applyClientAuthentication(IdentityProviderClientAuth? clientAuth, string clientId,
        map<string> form, map<string|string[]> headers) returns error? {
    if clientAuth is () {
        form["client_id"] = clientId;
        return;
    }
    if clientAuth.authMethod == mcp:CLIENT_SECRET_POST {
        form["client_id"] = clientId;
        form["client_secret"] = clientAuth.clientSecret;
        return;
    }
    string credentials = (check encodeValue(clientId)) + ":" + (check encodeValue(clientAuth.clientSecret));
    headers["Authorization"] = "Basic " + credentials.toBytes().toBase64();
}

// Describes a token endpoint error response (RFC 6749 section 5.2).
isolated function tokenEndpointError(string tokenEndpoint, int statusCode, json|error payload) returns error {
    string? errorCode = ();
    string? description = ();
    if payload is map<json> {
        json codeValue = payload["error"] ?: ();
        errorCode = codeValue is string ? codeValue : ();
        json descriptionValue = payload["error_description"] ?: ();
        description = descriptionValue is string ? descriptionValue : ();
    }
    string detail = errorCode is () ? string `status ${statusCode}`
        : (description is () ? string `'${errorCode}'` : string `'${errorCode}': ${description}`);
    return error(string `Token endpoint '${tokenEndpoint}' rejected the request with ${detail}.`);
}

// Discovers the Identity Provider metadata from the RFC 8414 and OpenID Connect locations. The issuer
// must match exactly; a mismatch fails without trying another candidate.
isolated function discoverIdentityProviderMetadata(string issuer, mcp:IdentityProviderConfig config,
        mcp:ClientObserver? observer) returns IdentityProviderMetadata|error {
    string[] candidates = check buildMetadataUrls(issuer);
    error? lastError = ();
    foreach string candidate in candidates {
        json|error payload = fetchMetadata(candidate, config, observer);
        if payload is error {
            lastError = payload;
            continue;
        }
        IdentityProviderMetadata|error metadata = payload.cloneWithType();
        if metadata is error {
            lastError = error(string `Authorization server metadata at '${candidate}' is not well formed.`,
                metadata);
            continue;
        }
        if metadata.issuer != issuer {
            return error(string `Authorization server metadata at '${candidate}' ` +
                string `declares issuer '${metadata.issuer}', which does not match the requested ` +
                string `issuer '${issuer}'.`);
        }
        return metadata;
    }
    error? cause = lastError;
    if cause is error {
        return error(string `Failed to discover authorization server metadata for '${issuer}': ${cause.message()}`,
            cause);
    }
    return error(string `Failed to discover authorization server metadata for '${issuer}'.`);
}

isolated function buildMetadataUrls(string issuer) returns string[]|error {
    UrlParts parts = check parseAbsoluteUrl(issuer);
    string path = parts.path == "/" ? "" : parts.path.endsWith("/")
        ? parts.path.substring(0, parts.path.length() - 1) : parts.path;
    if path == "" {
        return [
            parts.origin + OAUTH_AUTHORIZATION_SERVER_METADATA_PATH,
            parts.origin + OPENID_CONFIGURATION_PATH
        ];
    }
    return [
        parts.origin + OAUTH_AUTHORIZATION_SERVER_METADATA_PATH + path,
        parts.origin + OPENID_CONFIGURATION_PATH + path,
        parts.origin + path + OPENID_CONFIGURATION_PATH
    ];
}

isolated function fetchMetadata(string targetUrl, mcp:IdentityProviderConfig config,
        mcp:ClientObserver? observer) returns json|error {
    [string, string] [origin, path] = check splitUrl(targetUrl);
    http:Client httpClient = check createAuthClient(origin, config);
    notifyObserver(observer, {
        eventType: mcp:HTTP_REQUEST,
        eventTarget: mcp:IDENTITY_PROVIDER,
        eventUrl: targetUrl,
        httpMethod: "GET"
    });
    http:Response|error response = httpClient->get(path);
    if response is error {
        notifyObserver(observer, {
            eventType: mcp:CLIENT_ERROR,
            eventTarget: mcp:IDENTITY_PROVIDER,
            eventUrl: targetUrl,
            httpMethod: "GET",
            eventMessage: response.message()
        });
        return error(string `Request to '${targetUrl}' failed: ${response.message()}`, response);
    }
    notifyObserver(observer, {
        eventType: mcp:HTTP_RESPONSE,
        eventTarget: mcp:IDENTITY_PROVIDER,
        eventUrl: targetUrl,
        httpMethod: "GET",
        statusCode: response.statusCode,
        eventHeaders: sanitizedResponseHeaders(response)
    });
    if response.statusCode != http:STATUS_OK {
        string|error responseBody = response.getTextPayload();
        if responseBody is string {
            notifyObserver(observer, {
                eventType: mcp:HTTP_BODY,
                eventTarget: mcp:IDENTITY_PROVIDER,
                eventUrl: targetUrl,
                httpMethod: "GET",
                statusCode: response.statusCode,
                eventBody: responseBody,
                eventMessage: "Authorization metadata error response body"
            });
        }
        return error(string `Request to '${targetUrl}' returned status ${response.statusCode}.`);
    }
    json|error payload = response.getJsonPayload();
    if payload is error {
        return error(string `Response from '${targetUrl}' is not valid JSON.`, payload);
    }
    notifyObserver(observer, {
        eventType: mcp:HTTP_BODY,
        eventTarget: mcp:IDENTITY_PROVIDER,
        eventUrl: targetUrl,
        httpMethod: "GET",
        statusCode: response.statusCode,
        eventBody: payload.toJsonString(),
        eventMessage: "Authorization metadata"
    });
    return payload;
}

// Retries and redirects are disabled, and the endpoint must use HTTPS.
isolated function createAuthClient(string origin, mcp:IdentityProviderConfig config) returns http:Client|error {
    if !origin.toLowerAscii().startsWith("https://") {
        return error(string `'${origin}' does not use HTTPS. MCP authorization ` +
            string `endpoints must be served over HTTPS.`);
    }
    http:Client|error httpClient = new (origin, {
        httpVersion: config.httpVersion,
        timeout: config.timeout,
        secureSocket: config?.secureSocket,
        proxy: config?.proxy,
        retryConfig: (),
        followRedirects: ()
    });
    if httpClient is error {
        return error(string `Failed to create an HTTP client for '${origin}'.`, httpClient);
    }
    return httpClient;
}

isolated function validateHttpsUrl(string value, string fieldName) returns error? {
    UrlParts|error parsed = parseAbsoluteUrl(value);
    if parsed is error {
        return error(string `'${fieldName}' must be an absolute HTTPS URL.`, parsed);
    }
    if parsed.scheme != "https" {
        return error(string `'${fieldName}' must use HTTPS. Found '${value}'.`);
    }
    if parsed.query != "" {
        return error(string `'${fieldName}' must not include a query component. Found '${value}'.`);
    }
}

// Parses an absolute HTTP URL without losing its query or changing the case of its path.
isolated function parseAbsoluteUrl(string targetUrl) returns UrlParts|error {
    if targetUrl.includes("#") {
        return error(string `'${targetUrl}' contains a fragment.`);
    }
    int? schemeEnd = targetUrl.indexOf("://");
    if schemeEnd is () || schemeEnd == 0 {
        return error(string `'${targetUrl}' is not an absolute URL.`);
    }
    string scheme = targetUrl.substring(0, schemeEnd).toLowerAscii();
    if scheme != "http" && scheme != "https" {
        return error(string `'${targetUrl}' does not use HTTP or HTTPS.`);
    }
    int authorityStart = schemeEnd + 3;
    int? slash = targetUrl.indexOf("/", authorityStart);
    int? queryStart = targetUrl.indexOf("?", authorityStart);
    int authorityEnd = targetUrl.length();
    if slash is int && (queryStart is () || slash < queryStart) {
        authorityEnd = slash;
    } else if queryStart is int {
        authorityEnd = queryStart;
    }
    if authorityEnd == authorityStart {
        return error(string `'${targetUrl}' has no authority.`);
    }
    string authority = targetUrl.substring(authorityStart, authorityEnd);
    if authority.includes("@") {
        return error(string `'${targetUrl}' must not contain user information.`);
    }
    string path = "";
    if slash is int && slash == authorityEnd {
        path = targetUrl.substring(slash, queryStart is int ? queryStart : targetUrl.length());
    }
    return {
        scheme,
        origin: scheme + "://" + authority.toLowerAscii(),
        path,
        query: queryStart is int ? targetUrl.substring(queryStart) : ""
    };
}

isolated function splitUrl(string targetUrl) returns [string, string]|error {
    UrlParts parts = check parseAbsoluteUrl(targetUrl);
    return [parts.origin, (parts.path == "" ? "/" : parts.path) + parts.query];
}

// Observer failures are ignored, as in the MCP client.
isolated function notifyObserver(mcp:ClientObserver? observer, mcp:ClientEvent clientEvent) {
    if observer is mcp:ClientObserver {
        error? observerError = trap observer.onEvent(clientEvent.cloneReadOnly());
        if observerError is error {
            return;
        }
    }
}

// The redaction below matches the MCP client's, so events from this exchange read the same as its own.

isolated function sanitizedEventHeaders(map<string|string[]> eventHeaders) returns map<string|string[]> {
    map<string|string[]> sanitizedHeaders = {};
    foreach [string, string|string[]] [headerName, headerValue] in eventHeaders.entries() {
        string normalizedName = headerName.toLowerAscii();
        if normalizedName == "authorization" || normalizedName == "proxy-authorization" ||
                normalizedName == "cookie" || normalizedName == "set-cookie" ||
                normalizedName == "x-api-key" || normalizedName == "api-key" ||
                normalizedName == "x-auth-token" || normalizedName == "x-access-token" ||
                normalizedName == "x-goog-api-key" {
            sanitizedHeaders[headerName] = [REDACTED];
        } else {
            sanitizedHeaders[headerName] = headerValue.clone();
        }
    }
    return sanitizedHeaders;
}

isolated function sanitizedResponseHeaders(http:Response httpResponse) returns map<string|string[]> {
    map<string|string[]> responseHeaders = {};
    foreach string headerName in httpResponse.getHeaderNames() {
        string[]|error headerValues = httpResponse.getHeaders(headerName);
        if headerValues is string[] {
            responseHeaders[headerName] = headerValues;
        }
    }
    return sanitizedEventHeaders(responseHeaders);
}

isolated function sanitizedTokenParameters(map<string> tokenParameters) returns map<string> {
    map<string> sanitizedParameters = {};
    foreach [string, string] [parameterName, parameterValue] in tokenParameters.entries() {
        string normalizedName = parameterName.toLowerAscii();
        if normalizedName == "client_secret" || normalizedName == "client_assertion" ||
                normalizedName == "code" || normalizedName == "code_verifier" ||
                normalizedName == "refresh_token" || normalizedName == "access_token" ||
                normalizedName == "subject_token" || normalizedName == "actor_token" ||
                normalizedName == "assertion" {
            sanitizedParameters[parameterName] = REDACTED;
        } else {
            sanitizedParameters[parameterName] = parameterValue;
        }
    }
    return sanitizedParameters;
}

// The form body as sent, with credentials redacted. The redaction marker is left unencoded so it stays
// readable.
isolated function sanitizedTokenRequestBody(map<string> tokenParameters) returns string|error {
    string[] pairs = [];
    foreach [string, string] [parameterName, parameterValue] in sanitizedTokenParameters(tokenParameters).entries() {
        string encodedValue = parameterValue == REDACTED ? parameterValue : check encodeValue(parameterValue);
        pairs.push(parameterName + "=" + encodedValue);
    }
    return string:'join("&", ...pairs);
}

// JSON objects are reported with their tokens redacted. Other bodies are reported only for error
// responses, which carry no tokens.
isolated function tokenResponseEventBody(json|error payload, string|error responseText, int statusCode)
        returns string? {
    if payload is map<json> {
        return redactedTokenResponse(payload).toJsonString();
    }
    if statusCode != http:STATUS_OK && responseText is string && responseText != "" {
        return responseText;
    }
    return ();
}
