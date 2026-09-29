import ballerina/mcp;

public type ConnectionState "connecting"|"awaiting_authorization"|"connected"|"failed"|"closed";

public type NoAuthConfig record {|
    "none" authType = "none";
|};

public type ClientSecretAuthentication record {|
    mcp:ClientSecretAuthMethod authMethod;
    string clientSecret;
|};

public type CimdProfile CimdConfidentialProfile|"none";

public type CimdConfidentialProfile CimdPrivateKeyJwtProfile|CimdMutualTlsProfile;

public type CimdPrivateKeyJwtProfile "jwks"|"jwks_uri";

public type CimdMutualTlsProfile "mtls_jwks"|"mtls_jwks_uri";

public type CimdProfileInfo record {|
    CimdProfile id;
    string label;
    string description;
    string url;
    string tokenEndpointAuthMethod;
    string redirectUri;
    boolean supportsClientCredentials;
    // SHA-256 thumbprint (x5t#S256) of the certificate a mutual TLS profile presents
    string? certificateThumbprint = ();
|};

public type AuthorizationCodeAuthConfig record {|
    "authorization_code" authType;
    string clientId;
    string issuer;
    string redirectUri;
    ClientSecretAuthentication clientAuth;
    string[] scopes = [];
|};

public type CimdAuthorizationCodeAuthConfig record {|
    "cimd_authorization_code" authType;
    CimdProfile profile;
    string[] scopes = [];
|};

public type ClientCredentialsAuthConfig record {|
    "client_credentials" authType;
    string clientId;
    string issuer;
    ClientSecretAuthentication clientAuth;
    string[] scopes = [];
|};

public type CimdClientCredentialsAuthConfig record {|
    "cimd_client_credentials" authType;
    CimdConfidentialProfile profile;
    string[] scopes = [];
|};

// The enterprise Identity Provider of an enterprise-managed authorization (ID-JAG) connection. The
// inspector signs the user in there (OpenID Connect, leg 1) and exchanges the ID token for an ID-JAG
// (leg 2); the MCP client then redeems the ID-JAG at the resource authorization server (leg 3).
public type IdentityProviderSettings record {|
    string issuer;
    string clientId;
    // Omitted for a public client
    ClientSecretAuthentication clientAuth?;
    // Must be registered with the Identity Provider
    string redirectUri;
    string[] loginScopes = ["openid"];
|};

public type IdentityAssertionAuthConfig record {|
    "identity_assertion" authType;
    string clientId;
    string issuer;
    ClientSecretAuthentication clientAuth;
    IdentityProviderSettings identityProvider;
    string[] scopes = [];
|};

public type CimdIdentityAssertionAuthConfig record {|
    "cimd_identity_assertion" authType;
    CimdProfile profile;
    IdentityProviderSettings identityProvider;
    string[] scopes = [];
|};

public type AuthConfig NoAuthConfig|AuthorizationCodeAuthConfig|CimdAuthorizationCodeAuthConfig|
    ClientCredentialsAuthConfig|CimdClientCredentialsAuthConfig|IdentityAssertionAuthConfig|
    CimdIdentityAssertionAuthConfig;

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
