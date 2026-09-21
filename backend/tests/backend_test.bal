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
