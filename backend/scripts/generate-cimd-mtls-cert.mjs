// Creates the self-signed client certificate for the mutual TLS CIMD profiles
// (self_signed_tls_client_auth, RFC 8705 section 2.2) and the JWK Set that publishes it as x5c.
// Usage: node scripts/generate-cimd-mtls-cert.mjs [output-directory]
import { execFileSync } from "node:child_process";
import { X509Certificate, createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const outputDirectory = process.argv[2] ? resolve(process.argv[2]) : join(scriptDirectory, "..", "secrets");
const privateKeyPath = join(outputDirectory, "cimd-mtls-private-key.pem");
const certificatePath = join(outputDirectory, "cimd-mtls-certificate.pem");
const jwksPath = join(outputDirectory, "cimd-mtls-jwks.json");
const keyId = "mcp-inspector-mtls";
const validityDays = "730";

if ([privateKeyPath, certificatePath, jwksPath].some((path) => existsSync(path))) {
  throw new Error("CIMD mTLS material already exists. Remove it explicitly before rotating the certificate.");
}

mkdirSync(outputDirectory, { recursive: true });
execFileSync("openssl", [
  "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
  "-days", validityDays,
  "-subj", "/CN=Ballerina MCP Inspector",
  "-keyout", privateKeyPath,
  "-out", certificatePath,
], { stdio: "pipe" });
chmodSync(privateKeyPath, 0o600);

const certificate = new X509Certificate(readFileSync(certificatePath));
const thumbprint = createHash("sha256").update(certificate.raw).digest("base64url");
// RFC 8705 section 2.2.2: the certificate goes in x5c, and the JWK still carries the public key members.
const jwks = {
  keys: [{
    ...certificate.publicKey.export({ format: "jwk" }),
    kid: keyId,
    x5c: [certificate.raw.toString("base64")],
    "x5t#S256": thumbprint,
  }],
};
writeFileSync(jwksPath, `${JSON.stringify(jwks, null, 2)}\n`);

console.log(`Created ${privateKeyPath}`);
console.log(`Created ${certificatePath}`);
console.log(`Created ${jwksPath}`);
console.log(`Certificate SHA-256 thumbprint (x5t#S256): ${thumbprint}`);
