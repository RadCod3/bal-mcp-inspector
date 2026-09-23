import ballerina/lang.runtime;
import ballerina/mcp;

configurable int oauthCallbackTimeoutSeconds = 300;

isolated class OAuthCallbackBroker {
    private map<string> connectionByState = {};
    private map<string> stateByConnection = {};
    private map<readonly & mcp:AuthorizationCallbackParams> callbackByConnection = {};

    isolated function register(string connectionId, string state) {
        lock {
            string? existingState = self.stateByConnection[connectionId];
            if existingState is string {
                if self.connectionByState.hasKey(existingState) {
                    _ = self.connectionByState.remove(existingState);
                }
            }
            self.connectionByState[state] = connectionId;
            self.stateByConnection[connectionId] = state;
        }
    }

    isolated function complete(string state, mcp:AuthorizationCallbackParams callbackParams) returns error? {
        readonly & mcp:AuthorizationCallbackParams readonlyParams = callbackParams.cloneReadOnly();
        lock {
            string? connectionId = self.connectionByState[state];
            if connectionId is () {
                return error("Unknown or expired OAuth state");
            }
            _ = self.connectionByState.remove(state);
            if self.stateByConnection.hasKey(connectionId) {
                _ = self.stateByConnection.remove(connectionId);
            }
            self.callbackByConnection[connectionId] = readonlyParams;
        }
    }

    isolated function await(string connectionId) returns mcp:AuthorizationCallbackParams|error {
        int attempts = oauthCallbackTimeoutSeconds * 5;
        foreach int _ in 1 ... attempts {
            lock {
                readonly & mcp:AuthorizationCallbackParams? callbackParams = self.callbackByConnection[connectionId];
                if callbackParams is readonly & mcp:AuthorizationCallbackParams {
                    _ = self.callbackByConnection.remove(connectionId);
                    return callbackParams;
                }
                if !self.stateByConnection.hasKey(connectionId) {
                    return error("OAuth authorization was cancelled");
                }
            }
            runtime:sleep(0.2);
        }
        self.cancel(connectionId);
        return error("Timed out waiting for the OAuth callback");
    }

    isolated function cancel(string connectionId) {
        lock {
            string? state = self.stateByConnection[connectionId];
            if state is string {
                _ = self.stateByConnection.remove(connectionId);
                if self.connectionByState.hasKey(state) {
                    _ = self.connectionByState.remove(state);
                }
            }
            if self.callbackByConnection.hasKey(connectionId) {
                _ = self.callbackByConnection.remove(connectionId);
            }
        }
    }
}

final OAuthCallbackBroker oauthCallbackBroker = new;

isolated function authorizationState(string authorizationUrl) returns string|error {
    int? queryStart = authorizationUrl.indexOf("?");
    if queryStart is () {
        return error("Authorization URL does not contain a query string");
    }
    string query = authorizationUrl.substring(queryStart + 1);
    int stateStart = 0;
    if !query.startsWith("state=") {
        int? stateParameterStart = query.indexOf("&state=");
        if stateParameterStart is () {
            return error("Authorization URL does not contain OAuth state");
        }
        stateStart = stateParameterStart + 1;
    }
    string stateAndRemainder = query.substring(stateStart + 6);
    int? stateEnd = stateAndRemainder.indexOf("&");
    if stateEnd is int {
        return stateAndRemainder.substring(0, stateEnd);
    }
    return stateAndRemainder;
}

isolated function redirectHandler(string connectionId, string authorizationUrl) returns error? {
    string state = check authorizationState(authorizationUrl);
    oauthCallbackBroker.register(connectionId, state);
    connectionRegistry.setState(connectionId, "awaiting_authorization");
    appendLifecycleEvent(connectionId, "oauth.authorization_required", "awaiting_authorization",
            eventMessage = "Open the authorization URL to continue", authorizationUrl = authorizationUrl);
}

isolated function callbackHandler(string connectionId) returns mcp:AuthorizationCallbackParams|error {
    return oauthCallbackBroker.await(connectionId);
}
