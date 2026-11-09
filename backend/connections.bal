import ballerina/lang.runtime;
import ballerina/log;
import ballerina/mcp;
import ballerina/time;
import ballerina/uuid;

isolated class ConnectionSession {
    final string browserSessionId;
    final string connectionId;
    final string serverUrl;
    final mcp:StreamableHttpClient mcpClient;
    // The CIMD client the connection authorizes as, if any
    final CimdProfile? cimdProfile;
    private ConnectionState state = "connecting";
    private string? errorMessage = ();
    private (readonly & mcp:ConnectionInfo)? connectionInfo = ();
    private (readonly & mcp:ListToolsResult)? tools = ();

    isolated function init(string browserSessionId, string connectionId, string serverUrl,
            mcp:StreamableHttpClient mcpClient, CimdProfile? cimdProfile = ()) {
        self.browserSessionId = browserSessionId;
        self.connectionId = connectionId;
        self.serverUrl = serverUrl;
        self.mcpClient = mcpClient;
        self.cimdProfile = cimdProfile;
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
    // When each browser session last called the API, in monotonic seconds. An open tab polls its connection,
    // so a browser session that stops calling has been closed.
    private map<decimal> lastActiveByBrowserSession = {};

    isolated function add(ConnectionSession session) {
        lock {
            self.sessions[session.connectionId] = session;
        }
        self.touch(session.browserSessionId);
    }

    isolated function get(string connectionId) returns ConnectionSession? {
        lock {
            return self.sessions[connectionId];
        }
    }

    // Looks up a browser session's connection, and counts the lookup as activity by that browser session
    isolated function getOwned(string browserSessionId, string connectionId) returns ConnectionSession? {
        ConnectionSession? session = self.get(connectionId);
        if session is ConnectionSession && session.browserSessionId == browserSessionId {
            self.touch(browserSessionId);
            return session;
        }
        return ();
    }

    isolated function touch(string browserSessionId) {
        lock {
            self.lastActiveByBrowserSession[browserSessionId] = time:monotonicNow();
        }
    }

    # Returns the connections of browser sessions that have not called the API for the given time,
    # and forgets browser sessions that no longer have connections.
    #
    # + idleSeconds - How long a browser session must be inactive
    # + return - The idle connections
    isolated function idle(decimal idleSeconds) returns ConnectionSession[] {
        decimal cutoff = time:monotonicNow() - idleSeconds;
        readonly & string[] idleIds;
        lock {
            string[] ids = [];
            map<boolean> withConnections = {};
            foreach ConnectionSession session in self.sessions {
                withConnections[session.browserSessionId] = true;
                decimal lastActive = self.lastActiveByBrowserSession[session.browserSessionId] ?: 0d;
                if lastActive < cutoff {
                    ids.push(session.connectionId);
                }
            }
            foreach string browserSessionId in self.lastActiveByBrowserSession.keys() {
                if !withConnections.hasKey(browserSessionId) {
                    _ = self.lastActiveByBrowserSession.remove(browserSessionId);
                }
            }
            idleIds = ids.cloneReadOnly();
        }
        ConnectionSession[] idleSessions = [];
        foreach string connectionId in idleIds {
            ConnectionSession? session = self.get(connectionId);
            if session is ConnectionSession {
                idleSessions.push(session);
            }
        }
        return idleSessions;
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

    // Connections that aren't closed and authorize as one of the given CIMD clients
    isolated function usingCimdProfiles(CimdProfile[] profiles) returns ConnectionSession[] {
        ConnectionSession[] sessions = [];
        foreach string connectionId in self.connectionIds() {
            ConnectionSession? session = self.get(connectionId);
            if session is ConnectionSession && session.status().state != "closed" {
                CimdProfile? profile = session.cimdProfile;
                if profile is CimdProfile && profiles.indexOf(profile) is int {
                    sessions.push(session);
                }
            }
        }
        return sessions;
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
    mcp:PreRegisteredClientConfig clientConfig = {clientId: authConfig.clientId, issuer: authConfig.issuer};
    ClientSecretAuthentication? clientAuth = authConfig?.clientAuth;
    if clientAuth is ClientSecretAuthentication {
        clientConfig.clientAuth = {clientSecret: clientAuth.clientSecret, authMethod: clientAuth.authMethod};
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

isolated function createCimdAuthorizationCodeOAuthConfig(string connectionId,
        CimdAuthorizationCodeAuthConfig authConfig) returns mcp:OAuthConfig|error {
    CimdProfile profile = authConfig.profile;
    mcp:CimdClientConfig clientConfig = {url: cimdProfileUrl(profile)};
    if profile != "none" {
        clientConfig.clientAuth = check createCimdClientAuthentication(profile);
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
                clientAuth: check createCimdClientAuthentication(authConfig.profile)
            }
        },
        scopes: authConfig.scopes
    };
}

isolated function identityAssertionProvider(string connectionId, IdentityProviderSettings settings)
        returns mcp:IdentityAssertionProvider {
    final readonly & IdentityProviderSettings pinnedSettings = settings.cloneReadOnly();
    return isolated function(mcp:IdentityAssertionContext context) returns string|error {
        return provideIdJag(connectionId, pinnedSettings, context);
    };
}

isolated function createIdentityAssertionOAuthConfig(string connectionId, IdentityAssertionAuthConfig authConfig)
        returns mcp:OAuthConfig {
    return {
        grant: {
            clientConfig: {
                clientId: authConfig.clientId,
                issuer: authConfig.issuer,
                clientAuth: {
                    clientSecret: authConfig.clientAuth.clientSecret,
                    authMethod: authConfig.clientAuth.authMethod
                }
            },
            assertionProvider: identityAssertionProvider(connectionId, authConfig.identityProvider)
        },
        scopes: authConfig.scopes
    };
}

isolated function createCimdIdentityAssertionOAuthConfig(string connectionId,
        CimdIdentityAssertionAuthConfig authConfig) returns mcp:OAuthConfig|error {
    CimdProfile profile = authConfig.profile;
    mcp:CimdClientConfig clientConfig = {url: cimdProfileUrl(profile)};
    if profile != "none" {
        clientConfig.clientAuth = check createCimdClientAuthentication(profile);
    }
    return {
        grant: {
            clientConfig,
            assertionProvider: identityAssertionProvider(connectionId, authConfig.identityProvider)
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
    } else if selectedAuth is IdentityAssertionAuthConfig {
        mcp:OAuthConfig oauthConfig = createIdentityAssertionOAuthConfig(connectionId, selectedAuth);
        mcpClient = check new (request.serverUrl, protocolMode = request.protocolMode, auth = oauthConfig,
            observer = observer
        );
    } else if selectedAuth is CimdIdentityAssertionAuthConfig {
        mcp:OAuthConfig oauthConfig = check createCimdIdentityAssertionOAuthConfig(connectionId, selectedAuth);
        mcpClient = check new (request.serverUrl, protocolMode = request.protocolMode, auth = oauthConfig,
            observer = observer
        );
    } else {
        return error("Unsupported authorization configuration");
    }
    CimdProfile? cimdProfile = selectedAuth is CimdAuthorizationCodeAuthConfig|CimdClientCredentialsAuthConfig|
        CimdIdentityAssertionAuthConfig ? selectedAuth.profile : ();
    eventStore.open(connectionId);
    ConnectionSession session = new (browserSessionId, connectionId, request.serverUrl, mcpClient, cimdProfile);
    connectionRegistry.add(session);
    appendLifecycleEvent(connectionId, "connection.connecting", "connecting");
    _ = start connect(session);
    return {connectionId, state: "connecting"};
}

isolated function connect(ConnectionSession session) {
    mcp:StreamableHttpClient mcpClient = session.mcpClient;
    mcp:ConnectionInfo|mcp:ClientError result = mcpClient->connect(
        clientInfo = {name: "WSO2 MCP Playground", version: "0.1.0"});
    if result is mcp:ClientError {
        if session.status().state == "closed" {
            return;
        }
        oauthCallbackBroker.cancel(session.connectionId);
        string message = errorChainMessage(result);
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

# Forgets a closed connection. Its event log stays readable for `closedEventRetentionSeconds`.
#
# + session - The closed connection
isolated function releaseConnection(ConnectionSession session) {
    idTokenStore.remove(session.connectionId);
    _ = connectionRegistry.remove(session.connectionId);
    eventStore.close(session.connectionId);
    _ = start expireEventJournal(session.connectionId);
}

// Connections whose browser tab has not called the API for this long are closed, so that tabs closed
// without disconnecting don't keep their clients and event logs in memory. 0 keeps connections forever.
configurable int connectionIdleTimeoutSeconds = 1800;

# Closes the connections of browser sessions that have stopped calling the API.
#
# + idleSeconds - How long a browser session must be inactive
isolated function closeIdleConnections(decimal idleSeconds) {
    foreach ConnectionSession session in connectionRegistry.idle(idleSeconds) {
        oauthCallbackBroker.cancel(session.connectionId);
        mcp:StreamableHttpClient mcpClient = session.mcpClient;
        mcp:ClientError? closeError = mcpClient->close();
        if closeError is mcp:ClientError {
            log:printWarn("Closing an idle connection failed", connectionId = session.connectionId,
                    'error = closeError);
        }
        session.setState("closed");
        appendLifecycleEvent(session.connectionId, "connection.closed", "closed",
                eventMessage = string `Closed after ${idleSeconds} seconds without requests from its browser tab`);
        releaseConnection(session);
    }
}

isolated function closeIdleConnectionsPeriodically() {
    decimal idleSeconds = <decimal>connectionIdleTimeoutSeconds;
    decimal interval = idleSeconds < 60d ? idleSeconds : 60d;
    while true {
        runtime:sleep(interval);
        closeIdleConnections(idleSeconds);
    }
}

function init() {
    if connectionIdleTimeoutSeconds > 0 {
        _ = start closeIdleConnectionsPeriodically();
    }
}

// Joins an error's message with those of its causes, so a wrapped failure such as an Identity Provider
// rejection is shown with its reason. A cause already quoted in the message before it is skipped.
isolated function errorChainMessage(error err) returns string {
    string message = err.message();
    error? cause = err.cause();
    while cause is error {
        string causeMessage = cause.message();
        if !message.includes(causeMessage) {
            message += " " + causeMessage;
        }
        cause = cause.cause();
    }
    return message;
}
