import ballerina/http;
import ballerina/lang.runtime;
import ballerina/mcp;
import ballerina/test;
import ballerina/time;
import ballerina/url;

const MOCK_IDP_ISSUER = "http://localhost:18090";
const MOCK_IDP_CODE = "mock-authorization-code";

// The nonce the mock Identity Provider puts in the ID token, set by the test from the sign-in URL.
isolated string mockIdTokenNonce = "";
isolated map<string>[] mockIdpTokenRequests = [];

listener http:Listener mockIdentityProviderListener = new (18090);

service / on mockIdentityProviderListener {
    resource function get \.well\-known/openid\-configuration() returns json => {
        issuer: MOCK_IDP_ISSUER,
        authorization_endpoint: MOCK_IDP_ISSUER + "/authorize",
        token_endpoint: MOCK_IDP_ISSUER + "/token"
    };

    resource function post token(http:Request request) returns http:Ok|http:BadRequest|error {
        map<string> form = check request.getFormParams();
        lock {
            mockIdpTokenRequests.push(form.clone());
        }
        if form["grant_type"] != "authorization_code" || form["code"] != MOCK_IDP_CODE ||
                !form.hasKey("code_verifier") {
            return <http:BadRequest>{body: {'error: "invalid_grant"}};
        }
        string nonce;
        lock {
            nonce = mockIdTokenNonce;
        }
        return <http:Ok>{
            body: {
                id_token: unsignedJwt({sub: "user-1", nonce, exp: time:utcNow()[0] + 3600}),
                access_token: "idp-access-token",
                token_type: "Bearer"
            }
        };
    }
}

function unsignedJwt(map<json> claims) returns string =>
    string `${toBase64Url({alg: "none"}.toJsonString().toBytes())}.${toBase64Url(claims.toJsonString().toBytes())}.signature`;

final readonly & IdentityProviderSettings mockIdentityProvider = {
    issuer: MOCK_IDP_ISSUER,
    clientId: "idp-client",
    clientAuth: {authMethod: mcp:CLIENT_SECRET_POST, clientSecret: "idp-secret"},
    redirectUri: "http://localhost:8080/callback",
    loginScopes: ["openid", "email"]
};

// Waits for the sign-in URL the backend asks the user to open.
function awaitAuthorizationUrl(string connectionId) returns string|error {
    foreach int _ in 1 ... 50 {
        foreach InspectorEvent event in eventStore.after(connectionId, 0) ?: [] {
            string? authorizationUrl = event.authorizationUrl;
            if authorizationUrl is string {
                return authorizationUrl;
            }
        }
        runtime:sleep(0.1);
    }
    return error("The sign-in URL was not published.");
}

function queryParams(string target) returns map<string>|error {
    map<string> params = {};
    int? queryStart = target.indexOf("?");
    foreach string pair in re `&`.split(queryStart is int ? target.substring(queryStart + 1) : "") {
        int? separator = pair.indexOf("=");
        if separator is int {
            params[pair.substring(0, separator)] =
                check url:decode(re `\+`.replaceAll(pair.substring(separator + 1), " "), "UTF-8");
        }
    }
    return params;
}

@test:Config {}
function testIdentityProviderSignIn() returns error? {
    string connectionId = "ema-sign-in";
    eventStore.open(connectionId);
    future<IdToken|error> signIn = start signInAtIdentityProvider(connectionId, mockIdentityProvider);

    // The sign-in URL is an OpenID Connect authorization request with PKCE.
    map<string> request = check queryParams(check awaitAuthorizationUrl(connectionId));
    test:assertEquals(request["response_type"], "code");
    test:assertEquals(request["client_id"], "idp-client");
    test:assertEquals(request["redirect_uri"], "http://localhost:8080/callback");
    test:assertEquals(request["scope"], "openid email");
    test:assertEquals(request["code_challenge_method"], "S256");

    // Act as the browser returning to the playground's callback.
    lock {
        mockIdTokenNonce = request["nonce"] ?: "";
    }
    string state = request["state"] ?: "";
    check oauthCallbackBroker.complete(state, {code: MOCK_IDP_CODE, state});
    IdToken idToken = check wait signIn;
    test:assertTrue(idToken.expiresAt is int);

    // The token request carries the PKCE verifier and the Identity Provider client's credentials.
    map<string>[] tokenRequests;
    lock {
        tokenRequests = mockIdpTokenRequests.clone();
    }
    map<string> tokenRequest = tokenRequests[tokenRequests.length() - 1];
    test:assertEquals(tokenRequest["client_id"], "idp-client");
    test:assertEquals(tokenRequest["client_secret"], "idp-secret");
    test:assertEquals(tokenRequest["redirect_uri"], "http://localhost:8080/callback");

    // Every Identity Provider request is recorded, with the code, verifier, and secret redacted.
    readonly & InspectorEvent[] events = eventStore.after(connectionId, 0) ?: [];
    boolean metadataRequested = false;
    boolean tokenRequested = false;
    boolean idTokenAcquired = false;
    boolean tokenResponseRecorded = false;
    foreach InspectorEvent event in events {
        if event.eventTarget != "identity_provider" {
            continue;
        }
        if event.eventType == "http.request" && event.httpMethod == "GET" {
            metadataRequested = event.eventUrl == MOCK_IDP_ISSUER + "/.well-known/openid-configuration";
        }
        if event.eventType == "http.request" && event.httpMethod == "POST" {
            tokenRequested = true;
            string body = event.eventBody ?: "";
            test:assertFalse(body.includes(MOCK_IDP_CODE));
            test:assertFalse(body.includes("idp-secret"));
            test:assertFalse(body.includes(tokenRequest["code_verifier"] ?: "missing"));
            test:assertEquals(event.eventHeaders["Content-Type"], "application/x-www-form-urlencoded");
            // Recorded form-encoded as sent, with the redaction markers left readable.
            test:assertTrue(body.includes("grant_type=authorization_code"));
            test:assertTrue(body.includes("code=[REDACTED]"));
        }
        if event.eventType == "http.body" && event.httpMethod == "POST" {
            tokenResponseRecorded = true;
            map<json> response = check (check (event.eventBody ?: "").fromJsonString()).ensureType();
            test:assertEquals(response["id_token"], REDACTED);
            test:assertEquals(response["access_token"], REDACTED);
            test:assertEquals(response["token_type"], "Bearer");
        }
        if event.eventType == "oauth.token_acquired" {
            idTokenAcquired = true;
        }
    }
    test:assertTrue(metadataRequested);
    test:assertTrue(tokenRequested);
    test:assertTrue(tokenResponseRecorded);
    test:assertTrue(idTokenAcquired);
    eventStore.remove(connectionId);
}

@test:Config {}
function testIdentityProviderSignInError() returns error? {
    string connectionId = "ema-sign-in-denied";
    eventStore.open(connectionId);
    future<IdToken|error> signIn = start signInAtIdentityProvider(connectionId, mockIdentityProvider);
    map<string> request = check queryParams(check awaitAuthorizationUrl(connectionId));
    string state = request["state"] ?: "";
    check oauthCallbackBroker.complete(state, {state, 'error: "access_denied", errorDescription: "Denied"});

    IdToken|error result = wait signIn;
    test:assertTrue(result is error);
    if result is error {
        test:assertTrue(result.message().includes("access_denied"));
    }
    eventStore.remove(connectionId);
}

@test:Config {}
function testIdentityAssertionConfiguration() returns error? {
    IdentityAssertionAuthConfig preRegistered = {
        authType: "identity_assertion",
        clientId: "resource-client",
        issuer: "https://auth.example",
        clientAuth: {authMethod: mcp:CLIENT_SECRET_BASIC, clientSecret: "secret"},
        identityProvider: mockIdentityProvider,
        scopes: ["todos.read"]
    };
    mcp:OAuthConfig oauthConfig = createIdentityAssertionOAuthConfig("connection-1", preRegistered);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant|mcp:IdentityAssertionGrant grant = oauthConfig.grant;
    test:assertTrue(grant is mcp:IdentityAssertionGrant);
    if grant is mcp:IdentityAssertionGrant {
        test:assertTrue(grant.clientConfig is mcp:PreRegisteredClientConfig);
    }
    test:assertEquals(oauthConfig.scopes, ["todos.read"]);

    CimdIdentityAssertionAuthConfig publicCimd = {
        authType: "cimd_identity_assertion",
        profile: "none",
        identityProvider: mockIdentityProvider
    };
    mcp:OAuthConfig cimdConfig = check createCimdIdentityAssertionOAuthConfig("connection-1", publicCimd);
    grant = cimdConfig.grant;
    test:assertTrue(grant is mcp:IdentityAssertionGrant);
    if grant is mcp:IdentityAssertionGrant {
        mcp:OAuthClientConfig clientConfig = grant.clientConfig;
        test:assertTrue(clientConfig is mcp:CimdClientConfig);
        if clientConfig is mcp:CimdClientConfig {
            test:assertEquals(clientConfig.url, cimdProfileUrl("none"));
            test:assertEquals(clientConfig?.clientAuth, ());
        }
    }
}

@test:Config {}
function testIdentityAssertionRequestBinding() returns error? {
    // The shape the frontend sends for a public Identity Provider client.
    json payload = {
        serverUrl: "https://mcp.example/mcp",
        auth: {
            authType: "cimd_identity_assertion",
            profile: "jwks",
            identityProvider: {issuer: MOCK_IDP_ISSUER, clientId: "idp-client", redirectUri: "http://localhost/cb"},
            scopes: []
        }
    };
    CreateConnectionRequest request = check payload.cloneWithType();
    AuthConfig auth = request.auth;
    test:assertTrue(auth is CimdIdentityAssertionAuthConfig);
    if auth is CimdIdentityAssertionAuthConfig {
        test:assertEquals(auth.identityProvider?.clientAuth, ());
        test:assertEquals(auth.identityProvider.loginScopes, ["openid"]);
    }
}

@test:Config {}
function testIdTokenStoreExpiry() {
    idTokenStore.set("ema-expiry", {token: "fresh", expiresAt: time:utcNow()[0] + 3600});
    test:assertEquals(idTokenStore.valid("ema-expiry"), "fresh");
    // A token within the renewal margin is treated as expired.
    idTokenStore.set("ema-expiry", {token: "stale", expiresAt: time:utcNow()[0] + 5});
    test:assertEquals(idTokenStore.valid("ema-expiry"), ());
    idTokenStore.remove("ema-expiry");
    test:assertEquals(idTokenStore.valid("ema-expiry"), ());
}

@test:Config {}
function testDecodedIdJagOmitsTheSignature() returns error? {
    string connectionId = "ema-decoded-id-jag";
    eventStore.open(connectionId);
    string signature = "c2lnbmF0dXJlLXRoYXQtbXVzdC1ub3QtYmUtbG9nZ2Vk";
    string encodedHeader = toBase64Url({alg: "RS256", typ: "oauth-id-jag+jwt"}.toJsonString().toBytes());
    string encodedPayload = toBase64Url({iss: MOCK_IDP_ISSUER, aud: "https://as.example", client_id: "mcp-client"}
        .toJsonString().toBytes());
    string idJag = string `${encodedHeader}.${encodedPayload}.${signature}`;
    recordDecodedIdJag(connectionId, idJag);
    recordDecodedIdJag(connectionId, "not-a-jwt");

    readonly & InspectorEvent[] events = eventStore.after(connectionId, 0) ?: [];
    eventStore.remove(connectionId);
    test:assertEquals(events.length(), 2);
    InspectorEvent decoded = events[0];
    test:assertEquals(decoded.eventType, TOKEN_DECODED_EVENT);
    test:assertEquals(decoded.eventTarget, IDENTITY_PROVIDER_TARGET);
    map<json> body = check (check (decoded.eventBody ?: "").fromJsonString()).ensureType();
    test:assertEquals(body["token"], "ID-JAG");
    test:assertEquals(body["header"], {alg: "RS256", typ: "oauth-id-jag+jwt"});
    test:assertEquals(body["payload"], {iss: MOCK_IDP_ISSUER, aud: "https://as.example", client_id: "mcp-client"});
    // Neither the token nor its signature is recorded.
    string recorded = events.toJsonString();
    test:assertFalse(recorded.includes(signature));
    test:assertFalse(recorded.includes(idJag));
    test:assertFalse(recorded.includes(encodedPayload));

    test:assertEquals(events[1].eventBody, ());
    test:assertFalse(events.toJsonString().includes("not-a-jwt"));
}
