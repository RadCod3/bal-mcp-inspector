import ballerina/http;
import ballerina/mcp;

configurable int servicePort = 8080;

listener http:Listener inspectorListener = new (servicePort);

service /api/v1 on inspectorListener {
    resource function get health() returns record {|string status;|} {
        return {status: "ok"};
    }

    resource isolated function get cimd/profiles() returns CimdProfileInfo[] {
        return listCimdProfiles();
    }

    resource isolated function get sessions/[string browserSessionId]/connections()
            returns ConnectionStatus[]|http:BadRequest {
        if !validBrowserSessionId(browserSessionId) {
            return {body: <ApiError>{message: "Invalid browser session ID"}};
        }
        return connectionRegistry.list(browserSessionId);
    }

    resource isolated function post sessions/[string browserSessionId]/connections(
            @http:Payload CreateConnectionRequest request)
            returns CreateConnectionResponse|http:BadRequest {
        if !validBrowserSessionId(browserSessionId) {
            return {body: <ApiError>{message: "Invalid browser session ID"}};
        }
        CreateConnectionResponse|error result = createConnection(browserSessionId, request);
        if result is error {
            return {body: <ApiError>{message: result.message()}};
        }
        return result;
    }

    resource isolated function get sessions/[string browserSessionId]/connections/[string connectionId]()
            returns ConnectionStatus|http:NotFound {
        ConnectionSession? session = connectionRegistry.getOwned(browserSessionId, connectionId);
        if session is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        return session.status();
    }

    resource isolated function get sessions/[string browserSessionId]/connections/[string connectionId]/events(
            int after = 0)
            returns readonly & InspectorEvent[]|http:NotFound {
        if connectionRegistry.getOwned(browserSessionId, connectionId) is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        readonly & InspectorEvent[]? events = eventStore.after(connectionId, after);
        if events is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        return events;
    }

    resource isolated function get sessions/[string browserSessionId]/connections/[string connectionId]/eventStream(
            int after = 0)
            returns stream<http:SseEvent, error?>|http:NotFound {
        if connectionRegistry.getOwned(browserSessionId, connectionId) is () || !eventStore.exists(connectionId) {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        stream<http:SseEvent, error?> eventStream = new (new EventIterator(connectionId, after));
        return eventStream;
    }

    resource isolated function get sessions/[string browserSessionId]/connections/[string connectionId]/tools()
            returns mcp:ListToolsResult|http:NotFound|http:Conflict|http:BadGateway {
        ConnectionSession? session = connectionRegistry.getOwned(browserSessionId, connectionId);
        if session is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        ConnectionStatus status = session.status();
        if status.state != "connected" {
            return <http:Conflict>{body: <ApiError>{message: string `Connection is ${status.state}`}};
        }
        mcp:StreamableHttpClient mcpClient = session.mcpClient;
        mcp:ListToolsResult|error result = trap mcpClient->listTools();
        restoreConnectedState(session);
        if result is error {
            appendLifecycleEvent(connectionId, "tools.list_failed", "connected", eventMessage = result.message());
            return <http:BadGateway>{body: <ApiError>{message: string `tools/list failed: ${result.message()}`}};
        }
        return result;
    }

    resource isolated function post sessions/[string browserSessionId]/connections/[string connectionId]/tools/call(
            @http:Payload mcp:CallToolParams params)
            returns mcp:CallToolResult|http:NotFound|http:Conflict|http:BadGateway {
        ConnectionSession? session = connectionRegistry.getOwned(browserSessionId, connectionId);
        if session is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        ConnectionStatus status = session.status();
        if status.state != "connected" {
            return <http:Conflict>{body: <ApiError>{message: string `Connection is ${status.state}`}};
        }
        mcp:StreamableHttpClient mcpClient = session.mcpClient;
        mcp:CallToolResult|error result = trap mcpClient->callTool(params);
        restoreConnectedState(session);
        if result is error {
            appendLifecycleEvent(connectionId, "tools.call_failed", "connected", eventMessage = result.message());
            return <http:BadGateway>{body: <ApiError>{message: string `tools/call failed: ${result.message()}`}};
        }
        return result;
    }

    resource isolated function delete sessions/[string browserSessionId]/connections/[string connectionId]()
            returns http:NoContent|http:NotFound|http:InternalServerError {
        ConnectionSession? session = connectionRegistry.getOwned(browserSessionId, connectionId);
        if session is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        oauthCallbackBroker.cancel(connectionId);
        mcp:StreamableHttpClient mcpClient = session.mcpClient;
        mcp:ClientError? closeError = mcpClient->close();
        if closeError is mcp:ClientError {
            session.setState("failed", closeError.message());
            appendLifecycleEvent(connectionId, "connection.failed", "failed",
                    eventMessage = closeError.message());
            return <http:InternalServerError>{body: <ApiError>{message: closeError.message()}};
        }
        session.setState("closed");
        appendLifecycleEvent(connectionId, "connection.closed", "closed");
        _ = connectionRegistry.removeOwned(browserSessionId, connectionId);
        eventStore.close(connectionId);
        _ = start expireEventJournal(connectionId);
        return <http:NoContent>{};
    }

    resource isolated function get oauth/callback(http:Request request) returns string|http:BadRequest {
        return completeOAuthCallback(request);
    }
}

service /cimd on inspectorListener {
    resource isolated function get clients/jwks() returns json|http:InternalServerError {
        return cimdDocumentResponse("jwks");
    }

    resource isolated function get clients/jwksUri() returns json|http:InternalServerError {
        return cimdDocumentResponse("jwks_uri");
    }

    resource isolated function get clients/none() returns json|http:InternalServerError {
        return cimdDocumentResponse("none");
    }

    resource isolated function get jwks() returns json|http:InternalServerError {
        json|error result = loadCimdJwks();
        if result is error {
            return <http:InternalServerError>{body: <ApiError>{message: result.message()}};
        }
        return result;
    }
}

service /callback on inspectorListener {
    resource isolated function get .(http:Request request) returns string|http:BadRequest {
        return completeOAuthCallback(request);
    }
}

isolated function cimdDocumentResponse(CimdProfile profile) returns json|http:InternalServerError {
    json|error result = buildCimdDocument(profile);
    if result is error {
        return <http:InternalServerError>{body: <ApiError>{message: result.message()}};
    }
    return result;
}

isolated function restoreConnectedState(ConnectionSession session) {
    if session.status().state == "awaiting_authorization" {
        session.setState("connected");
    }
}

isolated function validBrowserSessionId(string browserSessionId) returns boolean {
    int length = browserSessionId.length();
    return length >= 16 && length <= 128;
}

isolated function completeOAuthCallback(http:Request request) returns string|http:BadRequest {
    map<string[]> queryParams = request.getQueryParams();
    string? state = firstQueryValue(queryParams, "state");
    if state is () {
        return {body: <ApiError>{message: "OAuth callback is missing state"}};
    }
    mcp:AuthorizationCallbackParams callbackParams = {};
    string? code = firstQueryValue(queryParams, "code");
    string? issuer = firstQueryValue(queryParams, "iss");
    string? oauthError = firstQueryValue(queryParams, "error");
    string? errorDescription = firstQueryValue(queryParams, "error_description");
    callbackParams.state = state;
    if code is string {
        callbackParams.code = code;
    }
    if issuer is string {
        callbackParams.iss = issuer;
    }
    if oauthError is string {
        callbackParams.'error = oauthError;
    }
    if errorDescription is string {
        callbackParams.errorDescription = errorDescription;
    }
    error? completionError = trap oauthCallbackBroker.complete(state, callbackParams);
    if completionError is error {
        return {body: <ApiError>{message: completionError.message()}};
    }
    return "Authorization completed. You can close this window.";
}

isolated function firstQueryValue(map<string[]> queryParams, string name) returns string? {
    string[]? values = queryParams[name];
    if values is string[] && values.length() > 0 {
        return values[0];
    }
    return ();
}
