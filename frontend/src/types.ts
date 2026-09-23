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
export type RsaSigningAlgorithm = "RS256" | "RS384" | "RS512";

export type PrivateKeySource =
  | {
      sourceType: "key_file";
      path: string;
      password?: string;
    }
  | {
      sourceType: "key_store";
      path: string;
      password: string;
      keyAlias: string;
      keyPassword: string;
    };

export type NoClientAuthentication = { authMethod: "none" };
export type ClientSecretAuthentication = {
  authMethod: SecretMethod;
  clientSecret: string;
};
export type PrivateKeyJwtAuthentication = {
  authMethod: "private_key_jwt";
  algorithm: RsaSigningAlgorithm;
  keyId?: string;
  key: PrivateKeySource;
};

export type AuthConfig =
  | { authType: "none" }
  | {
      authType: "authorization_code";
      clientId: string;
      issuer: string;
      redirectUri: string;
      clientAuth: NoClientAuthentication | ClientSecretAuthentication | PrivateKeyJwtAuthentication;
      scopes: string[];
    }
  | {
      authType: "cimd_authorization_code";
      url: string;
      redirectUri: string;
      clientAuth: NoClientAuthentication | PrivateKeyJwtAuthentication;
      scopes: string[];
    }
  | {
      authType: "client_credentials";
      clientId: string;
      issuer: string;
      clientAuth: ClientSecretAuthentication | PrivateKeyJwtAuthentication;
      scopes: string[];
    }
  | {
      authType: "cimd_client_credentials";
      url: string;
      clientAuth: PrivateKeyJwtAuthentication;
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
