import ballerina/mcp;

public type ConnectionState "connecting"|"awaiting_authorization"|"connected"|"failed"|"closed";

public type NoAuthConfig record {|
    "none" authType = "none";
|};

public type NoClientAuthentication record {|
    "none" authMethod = "none";
|};

public type ClientSecretAuthentication record {|
    mcp:ClientSecretAuthMethod authMethod;
    string clientSecret;
|};

public type RsaSigningAlgorithm "RS256"|"RS384"|"RS512";

public type KeyFileSource record {|
    "key_file" sourceType;
    string path;
    string? password = ();
|};

public type KeyStoreSource record {|
    "key_store" sourceType;
    string path;
    string password;
    string keyAlias;
    string keyPassword;
|};

public type PrivateKeySource KeyFileSource|KeyStoreSource;

public type PrivateKeyJwtAuthentication record {|
    "private_key_jwt" authMethod;
    RsaSigningAlgorithm algorithm = "RS256";
    string? keyId = ();
    PrivateKeySource key;
|};

public type AuthorizationCodeClientAuthentication
    NoClientAuthentication|ClientSecretAuthentication|PrivateKeyJwtAuthentication;

public type ClientCredentialsClientAuthentication
    ClientSecretAuthentication|PrivateKeyJwtAuthentication;

public type CimdAuthorizationCodeClientAuthentication
    NoClientAuthentication|PrivateKeyJwtAuthentication;

public type AuthorizationCodeAuthConfig record {|
    "authorization_code" authType;
    string clientId;
    string issuer;
    string redirectUri;
    AuthorizationCodeClientAuthentication clientAuth = {};
    string[] scopes = [];
|};

public type CimdAuthorizationCodeAuthConfig record {|
    "cimd_authorization_code" authType;
    string url;
    string redirectUri;
    CimdAuthorizationCodeClientAuthentication clientAuth = {};
    string[] scopes = [];
|};

public type ClientCredentialsAuthConfig record {|
    "client_credentials" authType;
    string clientId;
    string issuer;
    ClientCredentialsClientAuthentication clientAuth;
    string[] scopes = [];
|};

public type CimdClientCredentialsAuthConfig record {|
    "cimd_client_credentials" authType;
    string url;
    PrivateKeyJwtAuthentication clientAuth;
    string[] scopes = [];
|};

public type AuthConfig NoAuthConfig|AuthorizationCodeAuthConfig|CimdAuthorizationCodeAuthConfig|
    ClientCredentialsAuthConfig|CimdClientCredentialsAuthConfig;

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
    (readonly & mcp:ConnectionInfo)? connectionInfo = ();
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
