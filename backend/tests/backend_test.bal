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
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant grant = oauthConfig.grant;
    test:assertTrue(grant is mcp:AuthorizationCodeGrant);
    if grant is mcp:AuthorizationCodeGrant {
        mcp:AuthorizationCodeClientConfig clientConfig = grant.clientConfig;
        test:assertTrue(clientConfig is mcp:CimdAuthorizationCodeConfig);
        if clientConfig is mcp:CimdAuthorizationCodeConfig {
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
    test:assertEquals(profiles.length(), 3);
    test:assertTrue(profiles[0].supportsClientCredentials);
    test:assertTrue(profiles[1].supportsClientCredentials);
    test:assertFalse(profiles[2].supportsClientCredentials);
}

@test:Config {}
function testPreRegisteredOAuthUsesClientSecrets() {
    AuthorizationCodeAuthConfig authorizationCode = {
        authType: "authorization_code",
        clientId: "client-1",
        issuer: "https://issuer.example",
        redirectUri: "http://localhost:8080/api/v1/oauth/callback",
        clientAuth: {authMethod: mcp:CLIENT_SECRET_BASIC, clientSecret: "secret"}
    };
    mcp:OAuthConfig authorizationCodeConfig =
        createAuthorizationCodeOAuthConfig("connection-1", authorizationCode);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant authorizationCodeGrant =
        authorizationCodeConfig.grant;
    test:assertTrue(authorizationCodeGrant is mcp:AuthorizationCodeGrant);
    if authorizationCodeGrant is mcp:AuthorizationCodeGrant {
        test:assertTrue(authorizationCodeGrant.clientConfig is mcp:PreRegisteredAuthorizationCodeConfig);
        test:assertTrue(authorizationCodeGrant.clientConfig?.clientAuth is mcp:ClientSecretConfig);
    }

    ClientCredentialsAuthConfig clientCredentials = {
        authType: "client_credentials",
        clientId: "client-1",
        issuer: "https://issuer.example",
        clientAuth: {authMethod: mcp:CLIENT_SECRET_POST, clientSecret: "secret"}
    };
    mcp:OAuthConfig clientCredentialsConfig = createClientCredentialsOAuthConfig(clientCredentials);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant clientCredentialsGrant =
        clientCredentialsConfig.grant;
    test:assertTrue(clientCredentialsGrant is mcp:ClientCredentialsGrant);
    if clientCredentialsGrant is mcp:ClientCredentialsGrant {
        test:assertTrue(clientCredentialsGrant.clientConfig is mcp:PreRegisteredClientCredentialsConfig);
        test:assertTrue(clientCredentialsGrant.clientConfig.clientAuth is mcp:ClientSecretConfig);
    }
}
