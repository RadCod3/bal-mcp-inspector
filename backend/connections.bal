import ballerina/mcp;
import ballerina/uuid;

isolated class ConnectionSession {
    final string browserSessionId;
    final string connectionId;
    final string serverUrl;
    final mcp:StreamableHttpClient mcpClient;
    private ConnectionState state = "connecting";
    private string? errorMessage = ();
    private (readonly & mcp:ConnectionInfo)? connectionInfo = ();
    private (readonly & mcp:ListToolsResult)? tools = ();

    isolated function init(string browserSessionId, string connectionId, string serverUrl,
            mcp:StreamableHttpClient mcpClient) {
        self.browserSessionId = browserSessionId;
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
                errorMessage: self.errorMessage,
                connectionInfo: self.connectionInfo
            };
        }
    }

    isolated function setState(ConnectionState state, string? errorMessage = ()) {
        lock {
            self.state = state;
            self.errorMessage = errorMessage;
        }
    }

    isolated function setConnected(mcp:ConnectionInfo connectionInfo) {
        lock {
            self.state = "connected";
            self.errorMessage = ();
            self.connectionInfo = connectionInfo.cloneReadOnly();
        }
    }

    isolated function cachedTools() returns (readonly & mcp:ListToolsResult)? {
        lock {
            return self.tools;
        }
    }

    isolated function cacheTools(mcp:ListToolsResult tools) {
        lock {
            self.tools = tools.cloneReadOnly();
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

    isolated function getOwned(string browserSessionId, string connectionId) returns ConnectionSession? {
        ConnectionSession? session = self.get(connectionId);
        if session is ConnectionSession && session.browserSessionId == browserSessionId {
            return session;
        }
        return ();
    }

    isolated function connectionIds() returns readonly & string[] {
        lock {
            string[] ids = [];
            foreach string connectionId in self.sessions.keys() {
                ids.push(connectionId);
            }
            return ids.cloneReadOnly();
        }
    }

    isolated function list(string browserSessionId) returns ConnectionStatus[] {
        ConnectionStatus[] statuses = [];
        foreach string connectionId in self.connectionIds() {
            ConnectionSession? session = self.getOwned(browserSessionId, connectionId);
            if session is ConnectionSession {
                statuses.push(session.status());
            }
        }
        return statuses;
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

    isolated function removeOwned(string browserSessionId, string connectionId) returns ConnectionSession? {
        ConnectionSession? session = self.getOwned(browserSessionId, connectionId);
        if session is () {
            return ();
        }
        return self.remove(connectionId);
    }
}

final ConnectionRegistry connectionRegistry = new;

isolated function createAuthorizationCodeOAuthConfig(string connectionId, AuthorizationCodeAuthConfig authConfig)
        returns mcp:OAuthConfig {
    mcp:PreRegisteredAuthorizationCodeConfig clientConfig = {
        clientId: authConfig.clientId,
        issuer: authConfig.issuer,
        clientAuth: {
            clientSecret: authConfig.clientAuth.clientSecret,
            authMethod: authConfig.clientAuth.authMethod
        }
    };
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

isolated function createCimdAuthorizationCodeOAuthConfig(string connectionId,
        CimdAuthorizationCodeAuthConfig authConfig) returns mcp:OAuthConfig|error {
    mcp:CimdAuthorizationCodeConfig clientConfig = {url: cimdProfileUrl(authConfig.profile)};
    if authConfig.profile != "none" {
        clientConfig.clientAuth = check createCimdPrivateKeyJwtAuthentication();
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
            redirectUri: effectiveCimdRedirectUri(),
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
                    clientSecret: authConfig.clientAuth.clientSecret,
                    authMethod: authConfig.clientAuth.authMethod
                }
            }
        },
        scopes: authConfig.scopes
    };
}

isolated function createCimdClientCredentialsOAuthConfig(CimdClientCredentialsAuthConfig authConfig)
        returns mcp:OAuthConfig|error {
    return {
        grant: {
            clientConfig: {
                url: cimdProfileUrl(authConfig.profile),
                clientAuth: check createCimdPrivateKeyJwtAuthentication()
            }
        },
        scopes: authConfig.scopes
    };
}

isolated function createConnection(string browserSessionId, CreateConnectionRequest request)
        returns CreateConnectionResponse|error {
    string connectionId = uuid:createType4AsString();
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
    } else if selectedAuth is CimdAuthorizationCodeAuthConfig {
        mcp:OAuthConfig oauthConfig = check createCimdAuthorizationCodeOAuthConfig(connectionId, selectedAuth);
        mcpClient = check new (request.serverUrl, protocolMode = request.protocolMode, auth = oauthConfig,
            observer = observer
        );
    } else if selectedAuth is ClientCredentialsAuthConfig {
        mcp:OAuthConfig oauthConfig = createClientCredentialsOAuthConfig(selectedAuth);
        mcpClient = check new (request.serverUrl, protocolMode = request.protocolMode, auth = oauthConfig,
            observer = observer
        );
    } else if selectedAuth is CimdClientCredentialsAuthConfig {
        mcp:OAuthConfig oauthConfig = check createCimdClientCredentialsOAuthConfig(selectedAuth);
        mcpClient = check new (request.serverUrl, protocolMode = request.protocolMode, auth = oauthConfig,
            observer = observer
        );
    } else {
        return error("Unsupported authorization configuration");
    }
    eventStore.open(connectionId);
    ConnectionSession session = new (browserSessionId, connectionId, request.serverUrl, mcpClient);
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
        if session.status().state == "closed" {
            return;
        }
        oauthCallbackBroker.cancel(session.connectionId);
        string message = result.message();
        session.setState("failed", message);
        appendLifecycleEvent(session.connectionId, "connection.failed", "failed", eventMessage = message);
        return;
    }
    if session.status().state == "closed" {
        return;
    }
    session.setConnected(result);
    appendLifecycleEvent(session.connectionId, "connection.connected", "connected");
}
