import ballerina/mcp;

public type ConnectionState "connecting"|"awaiting_authorization"|"connected"|"failed"|"closed";

public type NoAuthConfig record {|
    "none" authType = "none";
|};

public type AuthorizationCodeAuthConfig record {|
    "authorization_code" authType;
    string clientId;
    string issuer;
    string redirectUri;
    string clientSecret?;
    mcp:ClientSecretAuthMethod clientSecretMethod = mcp:CLIENT_SECRET_BASIC;
    string[] scopes = [];
|};

public type ClientCredentialsAuthConfig record {|
    "client_credentials" authType;
    string clientId;
    string issuer;
    string clientSecret;
    mcp:ClientSecretAuthMethod clientSecretMethod = mcp:CLIENT_SECRET_BASIC;
    string[] scopes = [];
|};

public type AuthConfig NoAuthConfig|AuthorizationCodeAuthConfig|ClientCredentialsAuthConfig;

public type CreateConnectionRequest record {|
    string serverUrl;
    mcp:ProtocolMode protocolMode = "auto";
    AuthConfig auth = {};
|};

public type CreateConnectionResponse record {|
    string connectionId;
    ConnectionState state;
|};

public type ConnectionStatus record {|
    string connectionId;
    string serverUrl;
    ConnectionState state;
    string? errorMessage = ();
|};

public type ApiError record {|
    string message;
|};

public type InspectorEvent record {|
    int sequence;
    string timestamp;
    string connectionId;
    string eventType;
    string eventTarget;
    string? eventUrl = ();
    string? httpMethod = ();
    int? statusCode = ();
    map<string|string[]> eventHeaders = {};
    string? eventBody = ();
    string? eventMessage = ();
    string? authorizationUrl = ();
|};
