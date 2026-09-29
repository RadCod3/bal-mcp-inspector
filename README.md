# Ballerina MCP Inspector

A small, ephemeral inspector for configuring a Ballerina MCP client, inspecting transport and OAuth events, and invoking tools.

## Prerequisites

- Ballerina 2201.13.6
- Node.js 20+
- The observability-enabled `ballerina/mcp:2.0.0` package published to the local Ballerina repository

From the `module-ballerina-mcp` observability branch, publish the package with:

```powershell
.\gradlew.bat build -x test -PpublishToLocalCentral=true
```

## Run locally

Start the backend:

```powershell
cd backend
bal run
```

In a second terminal, start the frontend:

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. Vite proxies `/api` requests to the backend on port 8080.

For pre-registered authorization-code OAuth, register this callback URL with the provider:

```text
http://localhost:8080/api/v1/oauth/callback
```

Public CIMD clients use the metadata document's registered callback. The default backend configuration uses:

```text
http://localhost:8080/callback
```

The inspector exposes five backend-managed CIMD clients. Each client ID is the URL of its metadata document:

| Client | Metadata document | Token authentication |
| --- | --- | --- |
| Confidential, inline key | `<cimdPublicBaseUrl>/oauth/confidential-client.json` | `private_key_jwt`, public key in `jwks` |
| Confidential, key URL | `<cimdPublicBaseUrl>/oauth/confidential-client-jwks-uri.json` | `private_key_jwt`, public key at `jwks_uri` |
| Mutual TLS, inline certificate | `<cimdPublicBaseUrl>/oauth/mtls-client.json` | `self_signed_tls_client_auth`, certificate in `jwks` |
| Mutual TLS, certificate URL | `<cimdPublicBaseUrl>/oauth/mtls-client-jwks-uri.json` | `self_signed_tls_client_auth`, certificate at `jwks_uri` |
| Public | `<cimdPublicBaseUrl>/oauth/public-client.json` | `none` |

The public key set is served at `<cimdPublicBaseUrl>/oauth/jwks.json`. Generate the shared RSA signing material once:

```powershell
cd backend
node scripts/generate-cimd-keys.mjs
```

The mutual TLS clients use a separate key and a self-signed certificate ([RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) section 2.2). The certificate is published as `x5c` in `<cimdPublicBaseUrl>/oauth/mtls-jwks.json`, and the backend presents it only on connections to the token endpoint. Generating it needs `openssl` on the `PATH`:

```powershell
cd backend
node scripts/generate-cimd-mtls-cert.mjs
```

The script prints the certificate's SHA-256 thumbprint (`x5t#S256`), which the connection form also shows, so an authorization server operator can match it.

Copy `Config.example.toml` to `Config.toml` and set `cimdPublicBaseUrl` to the public HTTPS origin of the deployed backend. The backend itself hosts all five metadata documents, the public JWKS files, and the OAuth callback. By default the callback is `<cimdPublicBaseUrl>/callback`; `cimdRedirectUri` can override it when necessary. Authorization servers must be able to fetch the selected metadata document and, for the `jwks_uri` profiles, its JWKS endpoint. `Config.toml` and `backend/secrets/` are ignored by Git.

The inspector offers this OAuth client matrix:

| Client registration | Grant | Token authentication |
| --- | --- | --- |
| Pre-registered | Authorization code | `client_secret_basic` or `client_secret_post` |
| Pre-registered | Client credentials | `client_secret_basic` or `client_secret_post` |
| CIMD with inline `jwks` | Authorization code or client credentials | `private_key_jwt` or `self_signed_tls_client_auth` |
| CIMD with `jwks_uri` | Authorization code or client credentials | `private_key_jwt` or `self_signed_tls_client_auth` |
| CIMD public client | Authorization code | `none` |

The browser chooses only a CIMD profile. The RS256 signing key and the mutual TLS key remain on the backend; metadata endpoints expose only public JWKs and the certificate.

## Session behavior

The browser stores only a random browser session ID and the active connection ID. Client secrets are cleared from the form after submission. Authorization codes and tokens are handled by the backend and the MCP client.

All connections and event journals are held in memory. Restarting the backend intentionally clears them.
