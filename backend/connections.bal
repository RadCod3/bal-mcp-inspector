import ballerina/mcp;
import ballerina/uuid;

isolated class ConnectionSession {
    final string connectionId;
    final string serverUrl;
    final mcp:StreamableHttpClient mcpClient;
    private ConnectionState state = "connecting";
    private string? errorMessage = ();

    isolated function init(string connectionId, string serverUrl, mcp:StreamableHttpClient mcpClient) {
        self.connectionId = connectionId;
        self.serverUrl = serverUrl;
        self.mcpClient = mcpClient;
    }

    isolated function status() returns ConnectionStatus {
        lock {
            return {
                connectionId: self.connectionId,
                serverUrl: self.serverUrl,
                state: self.state,
                errorMessage: self.errorMessage
            };
        }
    }

    isolated function setState(ConnectionState state, string? errorMessage = ()) {
        lock {
            self.state = state;
            self.errorMessage = errorMessage;
        }
    }
}

isolated class ConnectionRegistry {
    private map<ConnectionSession> sessions = {};

    isolated function add(ConnectionSession session) {
        lock {
            self.sessions[session.connectionId] = session;
        }
    }

    isolated function get(string connectionId) returns ConnectionSession? {
        lock {
            return self.sessions[connectionId];
        }
    }

    isolated function setState(string connectionId, ConnectionState state, string? errorMessage = ()) {
        ConnectionSession? session = self.get(connectionId);
        if session is ConnectionSession {
            session.setState(state, errorMessage);
        }
    }

    isolated function remove(string connectionId) returns ConnectionSession? {
        lock {
            return self.sessions.remove(connectionId);
        }
    }
}

final ConnectionRegistry connectionRegistry = new;

isolated function createAuthorizationCodeOAuthConfig(string connectionId, AuthorizationCodeAuthConfig authConfig)
        returns mcp:OAuthConfig {
    mcp:PreRegisteredAuthorizationCodeConfig clientConfig = {
        clientId: authConfig.clientId,
        issuer: authConfig.issuer
    };
    string? clientSecret = authConfig.clientSecret;
    if clientSecret is string {
        clientConfig.clientAuth = <mcp:ClientSecretConfig>{
            clientSecret,
            authMethod: authConfig.clientSecretMethod
        };
    }
    mcp:AuthorizationRedirectHandler onRedirect = isolated function(string authorizationUrl) returns error? {
        return redirectHandler(connectionId, authorizationUrl);
    };
    mcp:AuthorizationCallbackHandler onCallback = isolated function() returns mcp:AuthorizationCallbackParams|error {
        return callbackHandler(connectionId);
    };
    return {
        grant: {
            clientConfig,
            redirectUri: authConfig.redirectUri,
            redirectHandler: onRedirect,
            callbackHandler: onCallback
        },
        scopes: authConfig.scopes
    };
}

isolated function createClientCredentialsOAuthConfig(ClientCredentialsAuthConfig authConfig) returns mcp:OAuthConfig {
    return {
        grant: {
            clientConfig: {
                clientId: authConfig.clientId,
                issuer: authConfig.issuer,
                clientAuth: {
                    clientSecret: authConfig.clientSecret,
                    authMethod: authConfig.clientSecretMethod
                }
            }
        },
        scopes: authConfig.scopes
    };
}

isolated function createConnection(CreateConnectionRequest request) returns CreateConnectionResponse|error {
    string connectionId = uuid:createType4AsString();
    eventStore.open(connectionId);
    mcp:ClientObserver observer = new InspectorClientObserver(connectionId);
    mcp:StreamableHttpClient mcpClient;
    AuthConfig selectedAuth = request.auth;
    if selectedAuth is NoAuthConfig {
        mcpClient = check new (request.serverUrl, protocolMode = request.protocolMode, observer = observer);
    } else if selectedAuth is AuthorizationCodeAuthConfig {
        mcp:OAuthConfig oauthConfig = createAuthorizationCodeOAuthConfig(connectionId, selectedAuth);
        mcpClient = check new (request.serverUrl, protocolMode = request.protocolMode, auth = oauthConfig,
            observer = observer
        );
    } else {
        mcp:OAuthConfig oauthConfig = createClientCredentialsOAuthConfig(selectedAuth);
        mcpClient = check new (request.serverUrl, protocolMode = request.protocolMode, auth = oauthConfig,
            observer = observer
        );
    }
    ConnectionSession session = new (connectionId, request.serverUrl, mcpClient);
    connectionRegistry.add(session);
    appendLifecycleEvent(connectionId, "connection.connecting", "connecting");
    _ = start connect(session);
    return {connectionId, state: "connecting"};
}

isolated function connect(ConnectionSession session) {
    mcp:StreamableHttpClient mcpClient = session.mcpClient;
    mcp:ConnectionInfo|mcp:ClientError result = mcpClient->connect(
        clientInfo = {name: "Ballerina MCP Inspector", version: "0.1.0"});
    if result is mcp:ClientError {
        string message = result.message();
        session.setState("failed", message);
        appendLifecycleEvent(session.connectionId, "connection.failed", "failed", eventMessage = message);
        return;
    }
    session.setState("connected");
    appendLifecycleEvent(session.connectionId, "connection.connected", "connected");
}
