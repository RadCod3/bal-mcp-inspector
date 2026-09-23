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

Public CIMD clients use the metadata document's registered callback. The default CIMD document uses:

```text
http://localhost:8080/callback
```

The inspector exposes the complete OAuth client matrix supported by the module:

| Client registration | Grant | Token authentication |
| --- | --- | --- |
| Pre-registered | Authorization code | None, `client_secret_basic`, `client_secret_post`, or `private_key_jwt` |
| Pre-registered | Client credentials | `client_secret_basic`, `client_secret_post`, or `private_key_jwt` |
| CIMD | Authorization code | None or `private_key_jwt` |
| CIMD | Client credentials | `private_key_jwt` |

Private-key JWT supports RSA `RS256`, `RS384`, and `RS512` signing with either a private-key file or a key store. Key paths are resolved on the backend host.

## Session behavior

The browser stores only a random browser session ID and the active connection ID. Client secrets are cleared from the form after submission. Authorization codes and tokens are handled by the backend and the MCP client.

All connections and event journals are held in memory. Restarting the backend intentionally clears them.
