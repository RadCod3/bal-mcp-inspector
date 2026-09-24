export type ConnectionState =
  | "connecting"
  | "awaiting_authorization"
  | "connected"
  | "failed"
  | "closed";

export interface ConnectionStatus {
  connectionId: string;
  serverUrl: string;
  state: ConnectionState;
  errorMessage?: string;
  connectionInfo?: {
    protocolVersion: string;
    serverInfo?: { name: string; version: string; title?: string };
    capabilities: Record<string, unknown>;
    instructions?: string;
  };
}

export interface CreateConnectionResponse {
  connectionId: string;
  state: ConnectionState;
}

export type ProtocolMode = "auto" | "modern" | "legacy";
export type SecretMethod = "client_secret_basic" | "client_secret_post";
export type CimdProfile = "jwks" | "jwks_uri" | "none";
export type CimdPrivateKeyProfile = Exclude<CimdProfile, "none">;

export type ClientSecretAuthentication = {
  authMethod: SecretMethod;
  clientSecret: string;
};

export interface CimdProfileInfo {
  id: CimdProfile;
  label: string;
  description: string;
  url: string;
  tokenEndpointAuthMethod: "private_key_jwt" | "none";
  redirectUri: string;
  supportsClientCredentials: boolean;
}

export type AuthConfig =
  | { authType: "none" }
  | {
      authType: "authorization_code";
      clientId: string;
      issuer: string;
      redirectUri: string;
      clientAuth: ClientSecretAuthentication;
      scopes: string[];
    }
  | {
      authType: "cimd_authorization_code";
      profile: CimdProfile;
      scopes: string[];
    }
  | {
      authType: "client_credentials";
      clientId: string;
      issuer: string;
      clientAuth: ClientSecretAuthentication;
      scopes: string[];
    }
  | {
      authType: "cimd_client_credentials";
      profile: CimdPrivateKeyProfile;
      scopes: string[];
    };

export interface CreateConnectionRequest {
  serverUrl: string;
  protocolMode: ProtocolMode;
  auth: AuthConfig;
}

export interface InspectorEvent {
  sequence: number;
  timestamp: string;
  connectionId: string;
  eventType: string;
  eventTarget: string;
  eventUrl?: string;
  httpMethod?: string;
  statusCode?: number;
  eventHeaders?: Record<string, string | string[]>;
  eventBody?: string;
  eventMessage?: string;
  authorizationUrl?: string;
}

export interface McpTool {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
}

export interface ListToolsResult {
  tools: McpTool[];
  nextCursor?: string;
}
