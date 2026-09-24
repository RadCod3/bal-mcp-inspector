import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const secretsDirectory = join(scriptDirectory, "..", "secrets");
const privateKeyPath = join(secretsDirectory, "cimd-private-key.pem");
const jwksPath = join(secretsDirectory, "cimd-jwks.json");
const keyId = "mcp-inspector-rs256";

if (existsSync(privateKeyPath) || existsSync(jwksPath)) {
  throw new Error("CIMD signing material already exists. Remove it explicitly before rotating the key.");
}

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicExponent: 0x10001,
});
const publicJwk = publicKey.export({ format: "jwk" });
const jwks = {
  keys: [{
    ...publicJwk,
    use: "sig",
    alg: "RS256",
    kid: keyId,
  }],
};

mkdirSync(secretsDirectory, { recursive: true });
writeFileSync(privateKeyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
writeFileSync(jwksPath, `${JSON.stringify(jwks, null, 2)}\n`);

console.log(`Created ${privateKeyPath}`);
console.log(`Created ${jwksPath}`);
