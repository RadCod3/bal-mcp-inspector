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
function testCimdAuthorizationCodeConfiguration() {
    CimdAuthorizationCodeAuthConfig authConfig = {
        authType: "cimd_authorization_code",
        url: "https://client.example/metadata.json",
        redirectUri: "http://localhost:8080/callback",
        scopes: ["openid"]
    };
    mcp:OAuthConfig oauthConfig = createCimdAuthorizationCodeOAuthConfig("connection-1", authConfig);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant grant = oauthConfig.grant;
    test:assertTrue(grant is mcp:AuthorizationCodeGrant);
    if grant is mcp:AuthorizationCodeGrant {
        mcp:AuthorizationCodeClientConfig clientConfig = grant.clientConfig;
        test:assertTrue(clientConfig is mcp:CimdAuthorizationCodeConfig);
        if clientConfig is mcp:CimdAuthorizationCodeConfig {
            test:assertEquals(clientConfig.url, authConfig.url);
        }
        test:assertEquals(grant.redirectUri, authConfig.redirectUri);
    }
}

@test:Config {}
function testPrivateKeyJwtTranslation() {
    PrivateKeyJwtAuthentication fileRequest = {
        authMethod: "private_key_jwt",
        algorithm: "RS384",
        keyId: "signing-key-1",
        key: {
            sourceType: "key_file",
            path: "./client-private.pem",
            password: "key-password"
        }
    };
    mcp:PrivateKeyJwtConfig fileAuth = createPrivateKeyJwtAuthentication(fileRequest);
    test:assertEquals(fileAuth.signatureConfig.algorithm.toString(), "RS384");
    test:assertEquals(fileAuth.keyId, "signing-key-1");

    PrivateKeyJwtAuthentication keyStoreRequest = {
        authMethod: "private_key_jwt",
        algorithm: "RS512",
        key: {
            sourceType: "key_store",
            path: "./client.p12",
            password: "store-password",
            keyAlias: "client-key",
            keyPassword: "key-password"
        }
    };
    mcp:PrivateKeyJwtConfig keyStoreAuth = createPrivateKeyJwtAuthentication(keyStoreRequest);
    test:assertEquals(keyStoreAuth.signatureConfig.algorithm.toString(), "RS512");
    test:assertEquals(keyStoreAuth.keyId, ());
}

@test:Config {}
function testCompleteOAuthClientConfigurationMatrix() {
    PrivateKeyJwtAuthentication privateKeyJwt = {
        authMethod: "private_key_jwt",
        key: {sourceType: "key_file", path: "./client-private.pem"}
    };

    AuthorizationCodeAuthConfig preRegisteredCode = {
        authType: "authorization_code",
        clientId: "client-1",
        issuer: "https://issuer.example",
        redirectUri: "http://localhost:8080/api/v1/oauth/callback",
        clientAuth: privateKeyJwt
    };
    mcp:OAuthConfig preRegisteredCodeConfig =
        createAuthorizationCodeOAuthConfig("connection-1", preRegisteredCode);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant preRegisteredCodeGrant = preRegisteredCodeConfig.grant;
    test:assertTrue(preRegisteredCodeGrant is mcp:AuthorizationCodeGrant);
    if preRegisteredCodeGrant is mcp:AuthorizationCodeGrant {
        test:assertTrue(preRegisteredCodeGrant.clientConfig is mcp:PreRegisteredAuthorizationCodeConfig);
        test:assertTrue(preRegisteredCodeGrant.clientConfig?.clientAuth is mcp:PrivateKeyJwtConfig);
    }

    ClientCredentialsAuthConfig preRegisteredCredentials = {
        authType: "client_credentials",
        clientId: "client-1",
        issuer: "https://issuer.example",
        clientAuth: {authMethod: mcp:CLIENT_SECRET_POST, clientSecret: "secret"}
    };
    mcp:OAuthConfig preRegisteredCredentialsConfig =
        createClientCredentialsOAuthConfig(preRegisteredCredentials);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant preRegisteredCredentialsGrant =
        preRegisteredCredentialsConfig.grant;
    test:assertTrue(preRegisteredCredentialsGrant is mcp:ClientCredentialsGrant);
    if preRegisteredCredentialsGrant is mcp:ClientCredentialsGrant {
        test:assertTrue(preRegisteredCredentialsGrant.clientConfig is mcp:PreRegisteredClientCredentialsConfig);
        test:assertTrue(preRegisteredCredentialsGrant.clientConfig.clientAuth is mcp:ClientSecretConfig);
    }

    CimdAuthorizationCodeAuthConfig cimdCode = {
        authType: "cimd_authorization_code",
        url: "https://client.example/metadata.json",
        redirectUri: "http://localhost:8080/callback",
        clientAuth: privateKeyJwt
    };
    mcp:OAuthConfig cimdCodeConfig = createCimdAuthorizationCodeOAuthConfig("connection-2", cimdCode);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant cimdCodeGrant = cimdCodeConfig.grant;
    test:assertTrue(cimdCodeGrant is mcp:AuthorizationCodeGrant);
    if cimdCodeGrant is mcp:AuthorizationCodeGrant {
        test:assertTrue(cimdCodeGrant.clientConfig is mcp:CimdAuthorizationCodeConfig);
        test:assertTrue(cimdCodeGrant.clientConfig?.clientAuth is mcp:PrivateKeyJwtConfig);
    }

    CimdClientCredentialsAuthConfig cimdCredentials = {
        authType: "cimd_client_credentials",
        url: "https://client.example/metadata.json",
        clientAuth: privateKeyJwt
    };
    mcp:OAuthConfig cimdCredentialsConfig = createCimdClientCredentialsOAuthConfig(cimdCredentials);
    mcp:ClientCredentialsGrant|mcp:AuthorizationCodeGrant cimdCredentialsGrant = cimdCredentialsConfig.grant;
    test:assertTrue(cimdCredentialsGrant is mcp:ClientCredentialsGrant);
    if cimdCredentialsGrant is mcp:ClientCredentialsGrant {
        test:assertTrue(cimdCredentialsGrant.clientConfig is mcp:CimdClientCredentialsConfig);
        test:assertTrue(cimdCredentialsGrant.clientConfig.clientAuth is mcp:PrivateKeyJwtConfig);
    }
}
