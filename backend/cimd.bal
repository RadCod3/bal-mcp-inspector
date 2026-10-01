import ballerina/crypto;
import ballerina/http;
import ballerina/io;
import ballerina/jwt;
import ballerina/lang.array;
import ballerina/lang.regexp;
import ballerina/mcp;

configurable string cimdPublicBaseUrl = "http://localhost:8080";
configurable string cimdRedirectUri = "";
configurable string cimdPrivateKeyPath = "./secrets/cimd-private-key.pem";
configurable string cimdPrivateKeyPassword = "";
configurable string cimdJwksPath = "./secrets/cimd-jwks.json";
configurable string cimdKeyId = "mcp-inspector-rs256";
configurable string cimdMtlsCertificatePath = "./secrets/cimd-mtls-certificate.pem";
configurable string cimdMtlsPrivateKeyPath = "./secrets/cimd-mtls-private-key.pem";
configurable string cimdMtlsPrivateKeyPassword = "";
configurable string cimdMtlsJwksPath = "./secrets/cimd-mtls-jwks.json";

const string CIMD_JWKS_PATH = "/oauth/confidential-client.json";
const string CIMD_JWKS_URI_PATH = "/oauth/confidential-client-jwks-uri.json";
const string CIMD_MTLS_JWKS_PATH = "/oauth/mtls-client.json";
const string CIMD_MTLS_JWKS_URI_PATH = "/oauth/mtls-client-jwks-uri.json";
const string CIMD_NONE_PATH = "/oauth/public-client.json";
const string CIMD_PUBLIC_KEYS_PATH = "/oauth/jwks.json";
const string CIMD_MTLS_CERTIFICATES_PATH = "/oauth/mtls-jwks.json";
const string CIMD_CALLBACK_PATH = "/callback";

const string PRIVATE_KEY_JWT = "private_key_jwt";
const string SELF_SIGNED_TLS_CLIENT_AUTH = "self_signed_tls_client_auth";

isolated function normalizedCimdBaseUrl() returns string {
    string baseUrl = cimdPublicBaseUrl.trim();
    while baseUrl.endsWith("/") {
        baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
    }
    return baseUrl;
}

isolated function cimdProfileUrl(CimdProfile profile) returns string {
    string path = profile == "jwks" ? CIMD_JWKS_PATH :
        profile == "jwks_uri" ? CIMD_JWKS_URI_PATH :
        profile == "mtls_jwks" ? CIMD_MTLS_JWKS_PATH :
        profile == "mtls_jwks_uri" ? CIMD_MTLS_JWKS_URI_PATH : CIMD_NONE_PATH;
    return normalizedCimdBaseUrl() + path;
}

isolated function cimdPublicKeysUrl() returns string {
    return normalizedCimdBaseUrl() + CIMD_PUBLIC_KEYS_PATH;
}

isolated function cimdMtlsCertificatesUrl() returns string {
    return normalizedCimdBaseUrl() + CIMD_MTLS_CERTIFICATES_PATH;
}

isolated function effectiveCimdRedirectUri() returns string {
    string configuredRedirectUri = cimdRedirectUri.trim();
    return configuredRedirectUri == ""
        ? normalizedCimdBaseUrl() + CIMD_CALLBACK_PATH
        : configuredRedirectUri;
}

isolated function listCimdProfiles() returns CimdProfileInfo[] {
    // Shown so an authorization server operator can match the certificate the playground presents.
    string|error thumbprint = cimdMtlsCertificateThumbprint();
    string? certificateThumbprint = thumbprint is string ? thumbprint : ();
    return [
        {
            id: "jwks",
            label: "Signed JWT, key in the document",
            description: "private_key_jwt. The document's jwks holds the playground's public key.",
            url: cimdProfileUrl("jwks"),
            tokenEndpointAuthMethod: PRIVATE_KEY_JWT,
            redirectUri: effectiveCimdRedirectUri(),
            supportsClientCredentials: true
        },
        {
            id: "jwks_uri",
            label: "Signed JWT, key at a JWKS URL",
            description: "private_key_jwt. The document's jwks_uri points to the playground's public keys.",
            url: cimdProfileUrl("jwks_uri"),
            tokenEndpointAuthMethod: PRIVATE_KEY_JWT,
            redirectUri: effectiveCimdRedirectUri(),
            supportsClientCredentials: true
        },
        {
            id: "mtls_jwks",
            label: "Mutual TLS, certificate in the document",
            description: "self_signed_tls_client_auth. The document's jwks holds the playground's certificate.",
            url: cimdProfileUrl("mtls_jwks"),
            tokenEndpointAuthMethod: SELF_SIGNED_TLS_CLIENT_AUTH,
            redirectUri: effectiveCimdRedirectUri(),
            supportsClientCredentials: true,
            certificateThumbprint
        },
        {
            id: "mtls_jwks_uri",
            label: "Mutual TLS, certificate at a JWKS URL",
            description: "self_signed_tls_client_auth. The document's jwks_uri points to the playground's certificate.",
            url: cimdProfileUrl("mtls_jwks_uri"),
            tokenEndpointAuthMethod: SELF_SIGNED_TLS_CLIENT_AUTH,
            redirectUri: effectiveCimdRedirectUri(),
            supportsClientCredentials: true,
            certificateThumbprint
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
    boolean mutualTls = profile is CimdMutualTlsProfile;
    map<json> document = {
        "client_id": cimdProfileUrl(profile),
        "client_name": "WSO2 MCP Playground",
        "client_uri": normalizedCimdBaseUrl(),
        "redirect_uris": [effectiveCimdRedirectUri()],
        "grant_types": grantTypes,
        "response_types": ["code"],
        "token_endpoint_auth_method": profile == "none" ? "none" :
            mutualTls ? SELF_SIGNED_TLS_CLIENT_AUTH : PRIVATE_KEY_JWT
    };
    if profile == "jwks" {
        document["jwks"] = suppliedJwks is () ? check loadCimdJwks() : suppliedJwks;
    } else if profile == "jwks_uri" {
        document["jwks_uri"] = cimdPublicKeysUrl();
    } else if profile == "mtls_jwks" {
        document["jwks"] = suppliedJwks is () ? check loadCimdMtlsJwks() : suppliedJwks;
    } else if profile == "mtls_jwks_uri" {
        document["jwks_uri"] = cimdMtlsCertificatesUrl();
    }
    if profile is CimdPrivateKeyJwtProfile {
        document["token_endpoint_auth_signing_alg"] = "RS256";
    }
    return document;
}

isolated function loadCimdJwks() returns json|error {
    json|error content = io:fileReadJson(cimdJwksPath);
    if content is error {
        return error(string `Could not read the configured CIMD JWKS at '${cimdJwksPath}'.`, content);
    }
    map<json>[] keys = check publicJwkSet(content, "CIMD JWKS");
    foreach map<json> key in keys {
        if key["kid"] == cimdKeyId {
            return content;
        }
    }
    return error(string `The configured CIMD JWKS contains no key with kid '${cimdKeyId}'.`);
}

# Loads the JWK Set that publishes the mutual TLS certificate (RFC 8705 section 2.2.2). One of its
# keys must carry the configured certificate as the first `x5c` entry, since that is the
# certificate the playground presents.
#
# + jwksPath - Location of the JWK Set
# + certificatePath - Location of the PEM certificate the playground presents
# + return - The JWK Set, or an error if it doesn't publish the configured certificate
isolated function loadCimdMtlsJwks(string jwksPath = cimdMtlsJwksPath,
        string certificatePath = cimdMtlsCertificatePath) returns json|error {
    json|error content = io:fileReadJson(jwksPath);
    if content is error {
        return error(string `Could not read the configured CIMD mTLS JWKS at '${jwksPath}'.`, content);
    }
    map<json>[] keys = check publicJwkSet(content, "CIMD mTLS JWKS");
    string certificate = check readCimdMtlsCertificate(certificatePath);
    foreach map<json> key in keys {
        json chain = key["x5c"];
        if chain is json[] && chain.length() > 0 && chain[0] == certificate {
            return content;
        }
    }
    return error(string `The configured CIMD mTLS JWKS has no key whose x5c holds the certificate at ` +
        string `'${certificatePath}'.`);
}

isolated function publicJwkSet(json content, string description) returns map<json>[]|error {
    if !(content is map<json>) {
        return error(string `The configured ${description} must be a JSON object.`);
    }
    json? keysValue = content["keys"];
    if !(keysValue is json[]) || keysValue.length() == 0 {
        return error(string `The configured ${description} must contain at least one public key.`);
    }
    map<json>[] keys = [];
    foreach json keyValue in keysValue {
        if !(keyValue is map<json>) {
            return error(string `Every configured ${description} key must be a JSON object.`);
        }
        if keyValue.hasKey("d") || keyValue.hasKey("p") || keyValue.hasKey("q") ||
                keyValue.hasKey("dp") || keyValue.hasKey("dq") || keyValue.hasKey("qi") ||
                keyValue.hasKey("oth") {
            return error(string `The configured ${description} contains private key material.`);
        }
        keys.push(keyValue);
    }
    return keys;
}

# Reads the mutual TLS certificate as the standard base64 DER encoding used by `x5c`.
#
# + certificatePath - Location of the PEM certificate
# + return - The encoded certificate, or an error if the file holds no PEM certificate
isolated function readCimdMtlsCertificate(string certificatePath = cimdMtlsCertificatePath) returns string|error {
    string|error pem = io:fileReadString(certificatePath);
    if pem is error {
        return error(string `Could not read the configured CIMD mTLS certificate at '${certificatePath}'.`, pem);
    }
    string beginMarker = "-----BEGIN CERTIFICATE-----";
    int? begin = pem.indexOf(beginMarker);
    int? end = pem.indexOf("-----END CERTIFICATE-----");
    if begin is () || end is () || end < begin {
        return error(string `The configured CIMD mTLS certificate at '${certificatePath}' is not a ` +
            string `PEM certificate.`);
    }
    return regexp:replaceAll(re `\s`, pem.substring(begin + beginMarker.length(), end), "");
}

# Computes the `x5t#S256` thumbprint of the mutual TLS certificate (RFC 8705 section 3.1).
#
# + certificatePath - Location of the PEM certificate
# + return - The base64url encoded SHA-256 hash of the DER certificate, or an error
isolated function cimdMtlsCertificateThumbprint(string certificatePath = cimdMtlsCertificatePath)
        returns string|error {
    byte[] der = check array:fromBase64(check readCimdMtlsCertificate(certificatePath));
    string encoded = crypto:hashSha256(der).toBase64();
    encoded = regexp:replaceAll(re `\+`, encoded, "-");
    encoded = regexp:replaceAll(re `/`, encoded, "_");
    return regexp:replaceAll(re `=`, encoded, "");
}

isolated function validateCimdSigningMaterial() returns error? {
    readonly & byte[]|error privateKey = io:fileReadBytes(cimdPrivateKeyPath);
    if privateKey is error {
        return error(string `Could not read the configured CIMD private key at '${cimdPrivateKeyPath}'.`,
            privateKey);
    }
    _ = check loadCimdJwks();
}

isolated function validateCimdMtlsMaterial() returns error? {
    readonly & byte[]|error privateKey = io:fileReadBytes(cimdMtlsPrivateKeyPath);
    if privateKey is error {
        return error(string `Could not read the configured CIMD mTLS private key at '${cimdMtlsPrivateKeyPath}'.`,
            privateKey);
    }
    _ = check loadCimdMtlsJwks();
}

isolated function createCimdClientAuthentication(CimdConfidentialProfile profile) returns mcp:CimdClientAuth|error {
    if profile is CimdMutualTlsProfile {
        return createCimdMutualTlsAuthentication();
    }
    return createCimdPrivateKeyJwtAuthentication();
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

isolated function createCimdMutualTlsAuthentication() returns mcp:MutualTlsConfig|error {
    check validateCimdMtlsMaterial();
    http:CertKey key = {certFile: cimdMtlsCertificatePath, keyFile: cimdMtlsPrivateKeyPath};
    if cimdMtlsPrivateKeyPassword != "" {
        key.keyPassword = cimdMtlsPrivateKeyPassword;
    }
    return {key, authMethod: mcp:SELF_SIGNED_TLS_CLIENT_AUTH};
}
