import ballerina/http;
import ballerina/mcp;

configurable int servicePort = 8080;

listener http:Listener inspectorListener = new (servicePort);

service /api/v1 on inspectorListener {
    resource function get health() returns record {|string status;|} {
        return {status: "ok"};
    }

    resource isolated function post connections(@http:Payload CreateConnectionRequest request)
            returns CreateConnectionResponse|http:BadRequest {
        CreateConnectionResponse|error result = createConnection(request);
        if result is error {
            return {body: <ApiError>{message: result.message()}};
        }
        return result;
    }

    resource isolated function get connections/[string connectionId]()
            returns ConnectionStatus|http:NotFound {
        ConnectionSession? session = connectionRegistry.get(connectionId);
        if session is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        return session.status();
    }

    resource isolated function get connections/[string connectionId]/events(int after = 0)
            returns readonly & InspectorEvent[]|http:NotFound {
        readonly & InspectorEvent[]? events = eventStore.after(connectionId, after);
        if events is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        return events;
    }

    resource isolated function get connections/[string connectionId]/eventStream(int after = 0)
            returns stream<http:SseEvent, error?>|http:NotFound {
        if !eventStore.exists(connectionId) {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        stream<http:SseEvent, error?> eventStream = new (new EventIterator(connectionId, after));
        return eventStream;
    }

    resource isolated function get connections/[string connectionId]/tools()
            returns mcp:ListToolsResult|http:NotFound|http:Conflict|http:InternalServerError {
        ConnectionSession? session = connectionRegistry.get(connectionId);
        if session is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        ConnectionStatus status = session.status();
        if status.state != "connected" {
            return <http:Conflict>{body: <ApiError>{message: string `Connection is ${status.state}`}};
        }
        mcp:StreamableHttpClient mcpClient = session.mcpClient;
        mcp:ListToolsResult|mcp:ClientError result = mcpClient->listTools();
        if result is mcp:ClientError {
            return <http:InternalServerError>{body: <ApiError>{message: result.message()}};
        }
        return result;
    }

    resource isolated function post connections/[string connectionId]/tools/call(
            @http:Payload mcp:CallToolParams params)
            returns mcp:CallToolResult|http:NotFound|http:Conflict|http:InternalServerError {
        ConnectionSession? session = connectionRegistry.get(connectionId);
        if session is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        ConnectionStatus status = session.status();
        if status.state != "connected" {
            return <http:Conflict>{body: <ApiError>{message: string `Connection is ${status.state}`}};
        }
        mcp:StreamableHttpClient mcpClient = session.mcpClient;
        mcp:CallToolResult|mcp:ClientError result = mcpClient->callTool(params);
        if result is mcp:ClientError {
            return <http:InternalServerError>{body: <ApiError>{message: result.message()}};
        }
        return result;
    }

    resource isolated function delete connections/[string connectionId]()
            returns http:NoContent|http:NotFound|http:InternalServerError {
        ConnectionSession? session = connectionRegistry.remove(connectionId);
        if session is () {
            return <http:NotFound>{body: <ApiError>{message: "Connection not found"}};
        }
        mcp:StreamableHttpClient mcpClient = session.mcpClient;
        mcp:ClientError? closeError = mcpClient->close();
        if closeError is mcp:ClientError {
            return <http:InternalServerError>{body: <ApiError>{message: closeError.message()}};
        }
        session.setState("closed");
        appendLifecycleEvent(connectionId, "connection.closed", "closed");
        eventStore.close(connectionId);
        return <http:NoContent>{};
    }

    resource isolated function get oauth/callback(http:Request request) returns string|http:BadRequest {
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
        error? completionError = oauthCallbackBroker.complete(state, callbackParams);
        if completionError is error {
            return {body: <ApiError>{message: completionError.message()}};
        }
        return "Authorization completed. You can close this window.";
    }
}

isolated function firstQueryValue(map<string[]> queryParams, string name) returns string? {
    string[]? values = queryParams[name];
    if values is string[] && values.length() > 0 {
        return values[0];
    }
    return ();
}
