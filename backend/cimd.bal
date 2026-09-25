import ballerina/io;
import ballerina/jwt;
import ballerina/mcp;

configurable string cimdPublicBaseUrl = "http://localhost:8080";
configurable string cimdRedirectUri = "";
configurable string cimdPrivateKeyPath = "./secrets/cimd-private-key.pem";
configurable string cimdPrivateKeyPassword = "";
configurable string cimdJwksPath = "./secrets/cimd-jwks.json";
configurable string cimdKeyId = "mcp-inspector-rs256";

const string CIMD_JWKS_PATH = "/oauth/confidential-client.json";
const string CIMD_JWKS_URI_PATH = "/oauth/confidential-client-jwks-uri.json";
const string CIMD_NONE_PATH = "/oauth/public-client.json";
const string CIMD_PUBLIC_KEYS_PATH = "/oauth/jwks.json";
const string CIMD_CALLBACK_PATH = "/callback";

isolated function normalizedCimdBaseUrl() returns string {
    string baseUrl = cimdPublicBaseUrl.trim();
    while baseUrl.endsWith("/") {
        baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
    }
    return baseUrl;
}

isolated function cimdProfileUrl(CimdProfile profile) returns string {
    string path = profile == "jwks" ? CIMD_JWKS_PATH :
        profile == "jwks_uri" ? CIMD_JWKS_URI_PATH : CIMD_NONE_PATH;
    return normalizedCimdBaseUrl() + path;
}

isolated function cimdPublicKeysUrl() returns string {
    return normalizedCimdBaseUrl() + CIMD_PUBLIC_KEYS_PATH;
}

isolated function effectiveCimdRedirectUri() returns string {
    string configuredRedirectUri = cimdRedirectUri.trim();
    return configuredRedirectUri == ""
        ? normalizedCimdBaseUrl() + CIMD_CALLBACK_PATH
        : configuredRedirectUri;
}

isolated function listCimdProfiles() returns CimdProfileInfo[] {
    return [
        {
            id: "jwks",
            label: "Signed JWT, key in the document",
            description: "private_key_jwt. The document's jwks holds the inspector's public key.",
            url: cimdProfileUrl("jwks"),
            tokenEndpointAuthMethod: "private_key_jwt",
            redirectUri: effectiveCimdRedirectUri(),
            supportsClientCredentials: true
        },
        {
            id: "jwks_uri",
            label: "Signed JWT, key at a JWKS URL",
            description: "private_key_jwt. The document's jwks_uri points to the inspector's public keys.",
            url: cimdProfileUrl("jwks_uri"),
            tokenEndpointAuthMethod: "private_key_jwt",
            redirectUri: effectiveCimdRedirectUri(),
            supportsClientCredentials: true
        },
        {
            id: "none",
            label: "None, public client",
            description: "No client authentication at the token endpoint. User sign-in only.",
            url: cimdProfileUrl("none"),
            tokenEndpointAuthMethod: "none",
            redirectUri: effectiveCimdRedirectUri(),
            supportsClientCredentials: false
        }
    ];
}

isolated function buildCimdDocument(CimdProfile profile, json? suppliedJwks = ()) returns json|error {
    string[] grantTypes = profile == "none"
        ? ["authorization_code", "refresh_token"]
        : ["authorization_code", "refresh_token", "client_credentials"];
    map<json> document = {
        "client_id": cimdProfileUrl(profile),
        "client_name": "Ballerina MCP Inspector",
        "client_uri": normalizedCimdBaseUrl(),
        "redirect_uris": [effectiveCimdRedirectUri()],
        "grant_types": grantTypes,
        "response_types": ["code"],
        "token_endpoint_auth_method": profile == "none" ? "none" : "private_key_jwt"
    };
    if profile == "jwks" {
        document["jwks"] = suppliedJwks is () ? check loadCimdJwks() : suppliedJwks;
    } else if profile == "jwks_uri" {
        document["jwks_uri"] = cimdPublicKeysUrl();
    }
    if profile != "none" {
        document["token_endpoint_auth_signing_alg"] = "RS256";
    }
    return document;
}

isolated function loadCimdJwks() returns json|error {
    json|error content = io:fileReadJson(cimdJwksPath);
    if content is error {
        return error(string `Could not read the configured CIMD JWKS at '${cimdJwksPath}'.`, content);
    }
    if !(content is map<json>) {
        return error("The configured CIMD JWKS must be a JSON object.");
    }
    json? keysValue = content["keys"];
    if !(keysValue is json[]) || keysValue.length() == 0 {
        return error("The configured CIMD JWKS must contain at least one public key.");
    }
    boolean matchingKeyFound = false;
    foreach json keyValue in keysValue {
        if !(keyValue is map<json>) {
            return error("Every configured CIMD JWK must be a JSON object.");
        }
        if keyValue.hasKey("d") || keyValue.hasKey("p") || keyValue.hasKey("q") ||
                keyValue.hasKey("dp") || keyValue.hasKey("dq") || keyValue.hasKey("qi") ||
                keyValue.hasKey("oth") {
            return error("The configured CIMD JWKS contains private key material.");
        }
        if keyValue["kid"] == cimdKeyId {
            matchingKeyFound = true;
        }
    }
    if !matchingKeyFound {
        return error(string `The configured CIMD JWKS contains no key with kid '${cimdKeyId}'.`);
    }
    return content;
}

isolated function validateCimdSigningMaterial() returns error? {
    readonly & byte[]|error privateKey = io:fileReadBytes(cimdPrivateKeyPath);
    if privateKey is error {
        return error(string `Could not read the configured CIMD private key at '${cimdPrivateKeyPath}'.`,
            privateKey);
    }
    _ = check loadCimdJwks();
}

isolated function createCimdPrivateKeyJwtAuthentication() returns mcp:PrivateKeyJwtConfig|error {
    check validateCimdSigningMaterial();
    record {|
        string keyFile;
        string keyPassword?;
    |} keyFileConfig = {keyFile: cimdPrivateKeyPath};
    if cimdPrivateKeyPassword != "" {
        keyFileConfig.keyPassword = cimdPrivateKeyPassword;
    }
    jwt:IssuerSignatureConfig signatureConfig = {
        algorithm: jwt:RS256,
        config: keyFileConfig
    };
    return {
        signatureConfig,
        keyId: cimdKeyId
    };
}
