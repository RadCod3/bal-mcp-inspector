import type {
  CimdProfileInfo,
  ConnectionStatus,
  CreateConnectionRequest,
  CreateConnectionResponse,
  ListToolsResult,
} from "./types";

const ROOT = "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${ROOT}${path}`, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...init?.headers,
    },
  });

  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const responseText = await response.text();
      if (responseText) {
        try {
          const body = JSON.parse(responseText) as { message?: string };
          message = body.message ?? responseText;
        } catch {
          message = responseText;
        }
      }
    } catch {
      // Keep the HTTP status when the response body cannot be read.
    }
    throw new Error(message);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const sessionPath = (sessionId: string) =>
  `/sessions/${encodeURIComponent(sessionId)}`;

const connectionPath = (sessionId: string, connectionId: string) =>
  `${sessionPath(sessionId)}/connections/${encodeURIComponent(connectionId)}`;

export const api = {
  listCimdProfiles() {
    return request<CimdProfileInfo[]>("/cimd/profiles");
  },

  listConnections(sessionId: string) {
    return request<ConnectionStatus[]>(`${sessionPath(sessionId)}/connections`);
  },

  createConnection(sessionId: string, body: CreateConnectionRequest) {
    return request<CreateConnectionResponse>(`${sessionPath(sessionId)}/connections`, {
      method: "POST",
      body: JSON.stringify(body),
    });
  },

  getConnection(sessionId: string, connectionId: string) {
    return request<ConnectionStatus>(connectionPath(sessionId, connectionId));
  },

  disconnect(sessionId: string, connectionId: string) {
    return request<void>(connectionPath(sessionId, connectionId), { method: "DELETE" });
  },

  listTools(sessionId: string, connectionId: string) {
    return request<ListToolsResult>(`${connectionPath(sessionId, connectionId)}/tools`);
  },

  callTool(
    sessionId: string,
    connectionId: string,
    name: string,
    argumentsValue: Record<string, unknown>,
  ) {
    return request<unknown>(`${connectionPath(sessionId, connectionId)}/tools/call`, {
      method: "POST",
      body: JSON.stringify({ name, arguments: argumentsValue }),
    });
  },

  eventStreamUrl(sessionId: string, connectionId: string, after: number) {
    return `${ROOT}${connectionPath(sessionId, connectionId)}/eventStream?after=${after}`;
  },
};
