import ballerina/http;
import ballerina/io;
import ballerina/lang.runtime;
import ballerina/mcp;
import ballerina/test;

@test:Config {}
function testAuthorizationStateExtraction() returns error? {
    string state = check authorizationState(
            "https://login.example/authorize?client_id=inspector&state=state-123&code_challenge=challenge");
    test:assertEquals(state, "state-123");
}

@test:Config {}
function testAuthorizationStateRequiresQueryParameter() {
    string|error result = authorizationState("https://login.example/authorize?client_id=inspector");
    test:assertTrue(result is error);
}

@test:Config {}
function testAuthorizationStateDoesNotMatchParameterSuffix() returns error? {
    string state = check authorizationState(
            "https://login.example/authorize?upstream_state=wrong&state=correct");
    test:assertEquals(state, "correct");
}

@test:Config {}
function testOAuthCallbackBrokerCorrelatesState() returns error? {
    OAuthCallbackBroker broker = new;
    broker.register("connection-1", "state-1");
    mcp:AuthorizationCallbackParams callbackParams = {code: "code-1", state: "state-1"};
    check broker.complete("state-1", callbackParams);

    mcp:AuthorizationCallbackParams result = check broker.await("connection-1");
    test:assertEquals(result.code, "code-1");
    test:assertEquals(result.state, "state-1");
}

@test:Config {}
function testOAuthCallbackBrokerRejectsUnknownState() {
    OAuthCallbackBroker broker = new;
    error? result = broker.complete("unknown", {code: "code-1", state: "unknown"});
    test:assertTrue(result is error);
}

@test:Config {}
function testOAuthCallbackBrokerCancellation() {
    OAuthCallbackBroker broker = new;
    broker.register("connection-1", "state-1");
    broker.cancel("connection-1");
    error? result = broker.complete("state-1", {code: "code-1", state: "state-1"});
    test:assertTrue(result is error);
    mcp:AuthorizationCallbackParams|error callbackResult = broker.await("connection-1");
    test:assertTrue(callbackResult is error);
}

@test:Config {}
function testClientObserverWritesStructuredEvent() {
    string connectionId = "observer-test";
    eventStore.open(connectionId);
    InspectorClientObserver observer = new (connectionId);
    readonly & mcp:ClientEvent clientEvent = {
        eventType: mcp:HTTP_RESPONSE,
        eventTarget: mcp:MCP_SERVER,
        eventUrl: "https://mcp.example/api",
        statusCode: 200,
        eventHeaders: {"content-type": "application/json"},
        eventBody: "{\"jsonrpc\":\"2.0\"}"
    };

    observer.onEvent(clientEvent);
    readonly & InspectorEvent[]? events = eventStore.after(connectionId, 0);
    test:assertTrue(events is readonly & InspectorEvent[]);
    if events is readonly & InspectorEvent[] {
        test:assertEquals(events.length(), 1);
        test:assertEquals(events[0].sequence, 1);
        test:assertEquals(events[0].eventType, "http.response");
        test:assertEquals(events[0].eventTarget, "mcp_server");
        test:assertEquals(events[0].statusCode, 200);
    }
    eventStore.close(connectionId);
}

@test:Config {}
function testLifecycleEventsAreSequenced() {
    string connectionId = "lifecycle-test";
    eventStore.open(connectionId);
    appendLifecycleEvent(connectionId, "connection.connecting", "connecting");
    appendLifecycleEvent(connectionId, "connection.connected", "connected");

    readonly & InspectorEvent[]? events = eventStore.after(connectionId, 1);
    test:assertTrue(events is readonly & InspectorEvent[]);
    if events is readonly & InspectorEvent[] {
        test:assertEquals(events.length(), 1);
        test:assertEquals(events[0].sequence, 2);
        test:assertEquals(events[0].eventType, "connection.connected");
    }
    eventStore.close(connectionId);
}

@test:Config {}
function testIdleConnectionsAreClosedAndReleased() returns error? {
    mcp:StreamableHttpClient mcpClient = check new ("http://localhost:65534/mcp");
    ConnectionSession idleSession = new ("browser-session-idle", "idle-connection",
        "http://localhost:65534/mcp", mcpClient);
    ConnectionSession activeSession = new ("browser-session-active", "active-connection",
        "http://localhost:65534/mcp", mcpClient);
    foreach ConnectionSession session in [idleSession, activeSession] {
        eventStore.open(session.connectionId);
        connectionRegistry.add(session);
    }
    runtime:sleep(1.2);
    // A request from the active tab keeps its connections open
    test:assertTrue(connectionRegistry.getOwned("browser-session-active", "active-connection") is ConnectionSession);

    closeIdleConnections(1);

    test:assertTrue(connectionRegistry.get("idle-connection") is ());
    test:assertEquals(idleSession.status().state, "closed");
    test:assertFalse(eventStore.isOpen("idle-connection"));
    readonly & InspectorEvent[] events = eventStore.after("idle-connection", 0) ?: [];
    test:assertEquals(events[events.length() - 1].eventType, "connection.closed");
    test:assertTrue(connectionRegistry.get("active-connection") is ConnectionSession);

    _ = connectionRegistry.remove(activeSession.connectionId);
    foreach ConnectionSession session in [idleSession, activeSession] {
        eventStore.remove(session.connectionId);
    }
}

@test:Config {}
function testCimdFetchIsRecordedForConnectionsUsingTheClient() returns error? {
    mcp:StreamableHttpClient mcpClient = check new ("http://localhost:65534/mcp");
    ConnectionSession jwksUriSession = new ("browser-session-1234", "cimd-fetch-jwks-uri",
        "http://localhost:65534/mcp", mcpClient, "jwks_uri");
    ConnectionSession publicSession = new ("browser-session-1234", "cimd-fetch-public",
        "http://localhost:65534/mcp", mcpClient, "none");
    foreach ConnectionSession session in [jwksUriSession, publicSession] {
        eventStore.open(session.connectionId);
        connectionRegistry.add(session);
    }
    http:Request request = new;
    request.setHeader("User-Agent", "Example-AS/1.0");
    request.setHeader("X-Forwarded-For", "203.0.113.7");

    recordCimdFetch(request, cimdPublicKeysUrl(), "jwks_uri", http:STATUS_OK);

    readonly & InspectorEvent[]? events = eventStore.after(jwksUriSession.connectionId, 0);
    test:assertTrue(events is readonly & InspectorEvent[]);
    if events is readonly & InspectorEvent[] {
        test:assertEquals(events.length(), 1);
        test:assertEquals(events[0].eventType, CIMD_FETCHED_EVENT);
        test:assertEquals(events[0].eventUrl, cimdPublicKeysUrl());
        test:assertEquals(events[0].statusCode, 200);
        test:assertEquals(events[0].eventHeaders["user-agent"], "Example-AS/1.0");
        test:assertEquals(events[0].eventMessage,
            "Received by the playground; user agent \"Example-AS/1.0\", forwarded for 203.0.113.7");
    }
    test:assertEquals(eventStore.after(publicSession.connectionId, 0), []);
    foreach ConnectionSession session in [jwksUriSession, publicSession] {
        _ = connectionRegistry.remove(session.connectionId);
        eventStore.remove(session.connectionId);
    }
}

@test:Config {}
function testFirstQueryValue() {
    map<string[]> queryParams = {
        "state": ["state-1"],
        "empty": []
    };
    test:assertEquals(firstQueryValue(queryParams, "state"), "state-1");
    test:assertEquals(firstQueryValue(queryParams, "empty"), ());
    test:assertEquals(firstQueryValue(queryParams, "missing"), ());
}

@test:Config {}
function testBrowserSessionIdValidation() {
    test:assertTrue(validBrowserSessionId("browser-session-123456"));
    test:assertFalse(validBrowserSessionId("short"));
}

@test:Config {}
function testRuntimeAuthorizationRestoresConnectedState() returns error? {
    mcp:StreamableHttpClient mcpClient = check new ("http://localhost:65534/mcp");
    ConnectionSession session = new ("browser-session-1234", "connection-1",
        "http://localhost:65534/mcp", mcpClient);
    session.setState("awaiting_authorization");

    restoreConnectedState(session);

    test:assertEquals(session.status().state, "connected");
}

@test:Config {}
function testCimdAuthorizationCodeConfiguration() returns error? {
    CimdAuthorizationCodeAuthConfig authConfig = {
        authType: "cimd_authorization_code",
        profile: "none",
        scopes: ["openid"]
    };
    mcp:OAuthConfig oauthConfig =
        check createCimdAuthorizationCodeOAuthConfig("connection-1", authConfig);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant|mcp:IdentityAssertionGrant grant = oauthConfig.grant;
    test:assertTrue(grant is mcp:AuthorizationCodeGrant);
    if grant is mcp:AuthorizationCodeGrant {
        mcp:OAuthClientConfig clientConfig = grant.clientConfig;
        test:assertTrue(clientConfig is mcp:CimdClientConfig);
        if clientConfig is mcp:CimdClientConfig {
            test:assertEquals(clientConfig.url, cimdProfileUrl("none"));
            test:assertEquals(clientConfig?.clientAuth, ());
        }
        test:assertEquals(grant.redirectUri, effectiveCimdRedirectUri());
    }
}

@test:Config {}
function testCimdProfileDocuments() returns error? {
    json jwks = {
        keys: [{
            kty: "RSA",
            use: "sig",
            alg: "RS256",
            kid: cimdKeyId,
            n: "test-modulus",
            e: "AQAB"
        }]
    };

    json inlineValue = check buildCimdDocument("jwks", jwks);
    test:assertTrue(inlineValue is map<json>);
    if inlineValue is map<json> {
        test:assertEquals(inlineValue["client_id"], cimdProfileUrl("jwks"));
        test:assertEquals(inlineValue["token_endpoint_auth_method"], "private_key_jwt");
        test:assertEquals(inlineValue["jwks"], jwks);
        test:assertFalse(inlineValue.hasKey("jwks_uri"));
    }

    json uriValue = check buildCimdDocument("jwks_uri");
    test:assertTrue(uriValue is map<json>);
    if uriValue is map<json> {
        test:assertEquals(uriValue["jwks_uri"], cimdPublicKeysUrl());
        test:assertFalse(uriValue.hasKey("jwks"));
    }

    json noneValue = check buildCimdDocument("none");
    test:assertTrue(noneValue is map<json>);
    if noneValue is map<json> {
        test:assertEquals(noneValue["token_endpoint_auth_method"], "none");
        test:assertFalse(noneValue.hasKey("jwks"));
        test:assertFalse(noneValue.hasKey("jwks_uri"));
    }
}

@test:Config {}
function testCimdProfileCapabilities() {
    CimdProfileInfo[] profiles = listCimdProfiles();
    test:assertEquals(profiles.map((profile) => profile.id), ["jwks", "jwks_uri", "mtls_jwks", "mtls_jwks_uri", "none"]);
    foreach CimdProfileInfo profile in profiles {
        test:assertEquals(profile.supportsClientCredentials, profile.id != "none");
    }
    test:assertEquals(profiles[2].tokenEndpointAuthMethod, "self_signed_tls_client_auth");
    test:assertEquals(profiles[3].tokenEndpointAuthMethod, "self_signed_tls_client_auth");
}

const MTLS_TEST_RESOURCES = "tests/resources/mtls/";

@test:Config {}
function testCimdMutualTlsDocuments() returns error? {
    json jwks = check loadCimdMtlsJwks(MTLS_TEST_RESOURCES + "cimd-mtls-jwks.json",
        MTLS_TEST_RESOURCES + "cimd-mtls-certificate.pem");

    json inlineValue = check buildCimdDocument("mtls_jwks", jwks);
    test:assertTrue(inlineValue is map<json>);
    if inlineValue is map<json> {
        test:assertEquals(inlineValue["client_id"], cimdProfileUrl("mtls_jwks"));
        test:assertEquals(inlineValue["token_endpoint_auth_method"], "self_signed_tls_client_auth");
        test:assertEquals(inlineValue["jwks"], jwks);
        test:assertFalse(inlineValue.hasKey("token_endpoint_auth_signing_alg"));
        test:assertEquals(inlineValue["grant_types"], ["authorization_code", "refresh_token", "client_credentials"]);
    }

    json uriValue = check buildCimdDocument("mtls_jwks_uri");
    test:assertTrue(uriValue is map<json>);
    if uriValue is map<json> {
        test:assertEquals(uriValue["jwks_uri"], cimdMtlsCertificatesUrl());
        test:assertFalse(uriValue.hasKey("jwks"));
    }
    test:assertNotEquals(cimdProfileUrl("mtls_jwks"), cimdProfileUrl("jwks"));
    test:assertNotEquals(cimdProfileUrl("mtls_jwks_uri"), cimdProfileUrl("jwks_uri"));
}

@test:Config {}
function testCimdMtlsJwksMustPublishTheCertificate() {
    json|error mismatched = loadCimdMtlsJwks(MTLS_TEST_RESOURCES + "cimd-mtls-jwks.json",
        MTLS_TEST_RESOURCES + "other-certificate.pem");
    test:assertTrue(mismatched is error);
    json|error notPem = loadCimdMtlsJwks(MTLS_TEST_RESOURCES + "cimd-mtls-jwks.json",
        MTLS_TEST_RESOURCES + "cimd-mtls-jwks.json");
    test:assertTrue(notPem is error);
}

@test:Config {}
function testCimdMtlsCertificateThumbprint() returns error? {
    json jwks = check io:fileReadJson(MTLS_TEST_RESOURCES + "cimd-mtls-jwks.json");
    json[] keys = check jwks.keys.ensureType();
    json expected = check keys[0].x5t\#S256;
    test:assertEquals(check cimdMtlsCertificateThumbprint(MTLS_TEST_RESOURCES + "cimd-mtls-certificate.pem"),
        expected);
}

@test:Config {}
function testPreRegisteredAuthorizationCodeAllowsPublicClient() {
    AuthorizationCodeAuthConfig authorizationCode = {
        authType: "authorization_code",
        clientId: "client-1",
        issuer: "https://issuer.example",
        redirectUri: "http://localhost:8080/callback"
    };
    mcp:OAuthConfig config = createAuthorizationCodeOAuthConfig("connection-1", authorizationCode);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant|mcp:IdentityAssertionGrant grant = config.grant;
    test:assertTrue(grant is mcp:AuthorizationCodeGrant);
    if grant is mcp:AuthorizationCodeGrant {
        test:assertTrue(grant.clientConfig is mcp:PreRegisteredClientConfig);
        test:assertEquals(grant.clientConfig?.clientAuth, ());
    }
}

@test:Config {}
function testPreRegisteredOAuthUsesClientSecrets() {
    AuthorizationCodeAuthConfig authorizationCode = {
        authType: "authorization_code",
        clientId: "client-1",
        issuer: "https://issuer.example",
        redirectUri: "http://localhost:8080/callback",
        clientAuth: {authMethod: mcp:CLIENT_SECRET_BASIC, clientSecret: "secret"}
    };
    mcp:OAuthConfig authorizationCodeConfig =
        createAuthorizationCodeOAuthConfig("connection-1", authorizationCode);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant|mcp:IdentityAssertionGrant authorizationCodeGrant =
        authorizationCodeConfig.grant;
    test:assertTrue(authorizationCodeGrant is mcp:AuthorizationCodeGrant);
    if authorizationCodeGrant is mcp:AuthorizationCodeGrant {
        test:assertTrue(authorizationCodeGrant.clientConfig is mcp:PreRegisteredClientConfig);
        test:assertTrue(authorizationCodeGrant.clientConfig?.clientAuth is mcp:ClientSecretConfig);
    }

    ClientCredentialsAuthConfig clientCredentials = {
        authType: "client_credentials",
        clientId: "client-1",
        issuer: "https://issuer.example",
        clientAuth: {authMethod: mcp:CLIENT_SECRET_POST, clientSecret: "secret"}
    };
    mcp:OAuthConfig clientCredentialsConfig = createClientCredentialsOAuthConfig(clientCredentials);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant|mcp:IdentityAssertionGrant clientCredentialsGrant =
        clientCredentialsConfig.grant;
    test:assertTrue(clientCredentialsGrant is mcp:ClientCredentialsGrant);
    if clientCredentialsGrant is mcp:ClientCredentialsGrant {
        test:assertTrue(clientCredentialsGrant.clientConfig is mcp:PreRegisteredClientCredentialsConfig);
        test:assertTrue(clientCredentialsGrant.clientConfig.clientAuth is mcp:ClientSecretConfig);
    }
}
