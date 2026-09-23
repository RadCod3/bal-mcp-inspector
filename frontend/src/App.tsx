import {
  ArrowRight,
  Braces,
  Check,
  ChevronRight,
  CircleAlert,
  CircleDot,
  CircleOff,
  Clock3,
  ExternalLink,
  KeyRound,
  ListFilter,
  LockKeyhole,
  Loader2,
  Moon,
  Pencil,
  Plus,
  Power,
  Radio,
  RefreshCw,
  Search,
  Send,
  Server,
  Sun,
  TerminalSquare,
  Trash2,
  Wrench,
  X,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import type {
  AuthConfig,
  ConnectionState,
  ConnectionStatus,
  CreateConnectionRequest,
  InspectorEvent,
  McpTool,
  PrivateKeyJwtAuthentication,
  ProtocolMode,
  RsaSigningAlgorithm,
} from "./types";

const SESSION_KEY = "balInspector.browserSessionId";
const CONNECTION_KEY = "balInspector.activeConnectionId";
const THEME_KEY = "balInspector.theme";

type Theme = "light" | "dark";

function initialTheme(): Theme {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored === "light" || stored === "dark") return stored;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

const EVENT_TYPES = [
  "http.request",
  "http.response",
  "http.body",
  "mcp.message",
  "oauth.challenge",
  "oauth.authorization_redirect",
  "oauth.authorization_callback",
  "oauth.token_acquired",
  "client.error",
  "connection.connecting",
  "connection.connected",
  "connection.failed",
  "connection.closed",
  "oauth.authorization_required",
  "tools.list_failed",
  "tools.call_failed",
];

type AuthType = "none" | "authorization_code" | "client_credentials" |
  "cimd_authorization_code" | "cimd_client_credentials";
type TokenAuthMethod = "none" | "client_secret_basic" | "client_secret_post" | "private_key_jwt";
type KeySourceType = "key_file" | "key_store";
type View = "events" | "tools";
type EventFilter = "all" | "http" | "mcp" | "oauth" | "errors";

interface ConnectionForm {
  serverUrl: string;
  protocolMode: ProtocolMode;
  authType: AuthType;
  clientId: string;
  clientSecret: string;
  issuer: string;
  redirectUri: string;
  scopes: string;
  tokenAuthMethod: TokenAuthMethod;
  cimdUrl: string;
  signingAlgorithm: RsaSigningAlgorithm;
  keyId: string;
  keySourceType: KeySourceType;
  keyFilePath: string;
  keyFilePassword: string;
  keyStorePath: string;
  keyStorePassword: string;
  keyAlias: string;
  keyPassword: string;
}

const DEFAULT_CIMD_URL = "https://mute-hall-afe0.tggallage1.workers.dev/metadata.json";
const STANDARD_CALLBACK_URL = "http://localhost:8080/api/v1/oauth/callback";
const CIMD_CALLBACK_URL = "http://localhost:8080/callback";

const initialForm: ConnectionForm = {
  serverUrl: "http://localhost:9090/mcp",
  protocolMode: "auto",
  authType: "none",
  clientId: "",
  clientSecret: "",
  issuer: "",
  redirectUri: STANDARD_CALLBACK_URL,
  scopes: "",
  tokenAuthMethod: "none",
  cimdUrl: DEFAULT_CIMD_URL,
  signingAlgorithm: "RS256",
  keyId: "",
  keySourceType: "key_file",
  keyFilePath: "",
  keyFilePassword: "",
  keyStorePath: "",
  keyStorePassword: "",
  keyAlias: "",
  keyPassword: "",
};

function privateKeyJwtConfig(form: ConnectionForm): PrivateKeyJwtAuthentication {
  return {
    authMethod: "private_key_jwt",
    algorithm: form.signingAlgorithm,
    keyId: form.keyId || undefined,
    key: form.keySourceType === "key_file"
      ? {
          sourceType: "key_file",
          path: form.keyFilePath,
          password: form.keyFilePassword || undefined,
        }
      : {
          sourceType: "key_store",
          path: form.keyStorePath,
          password: form.keyStorePassword,
          keyAlias: form.keyAlias,
          keyPassword: form.keyPassword,
        },
  };
}

function clearedSecrets(form: ConnectionForm): ConnectionForm {
  return {
    ...form,
    clientSecret: "",
    keyFilePassword: "",
    keyStorePassword: "",
    keyPassword: "",
  };
}

const stateLabels: Record<ConnectionState, string> = {
  connecting: "Connecting",
  awaiting_authorization: "Authorization needed",
  connected: "Connected",
  failed: "Failed",
  closed: "Closed",
};

function getBrowserSessionId() {
  const existing = localStorage.getItem(SESSION_KEY);
  if (existing) return existing;
  const value = crypto.randomUUID();
  localStorage.setItem(SESSION_KEY, value);
  return value;
}

function shortId(value: string) {
  return value.length > 12 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function formatTime(timestamp: string) {
  const date = new Date(timestamp);
  return Number.isNaN(date.valueOf())
    ? timestamp
    : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function eventCategory(event: InspectorEvent): Exclude<EventFilter, "all"> {
  if (event.eventType === "client.error" || event.eventType.endsWith(".failed") ||
      (event.statusCode !== undefined && event.statusCode >= 400 && event.statusCode !== 401)) return "errors";
  if (event.eventType.startsWith("oauth.")) return "oauth";
  if (event.eventType.startsWith("mcp.")) return "mcp";
  return "http";
}

interface EventGroup {
  id: number;
  kind: "exchange" | "milestone";
  events: InspectorEvent[];
  title: string;
  subtitle: string;
  category: Exclude<EventFilter, "all">;
  statusCode?: number;
}

function groupMatchesFilter(group: EventGroup, filter: EventFilter) {
  return filter === "all" || group.category === filter ||
    group.events.some((event) => eventCategory(event) === filter);
}

function eventHeader(event: InspectorEvent, name: string) {
  const entry = Object.entries(event.eventHeaders ?? {})
    .find(([headerName]) => headerName.toLowerCase() === name.toLowerCase())?.[1];
  return Array.isArray(entry) ? entry[0] : entry;
}

function parsedEventBody(event: InspectorEvent): Record<string, unknown> | null {
  if (!event.eventBody) return null;
  try {
    const value = JSON.parse(event.eventBody) as unknown;
    return value && !Array.isArray(value) && typeof value === "object"
      ? value as Record<string, unknown>
      : null;
  } catch {
    return null;
  }
}

function requestTitle(event: InspectorEvent) {
  const body = parsedEventBody(event);
  const method = eventHeader(event, "mcp-method") ??
    (typeof body?.method === "string" ? body.method : undefined);
  if (method) {
    const params = body?.params && typeof body.params === "object"
      ? body.params as Record<string, unknown>
      : null;
    const toolName = typeof params?.name === "string" ? params.name : undefined;
    const labels: Record<string, string> = {
      "server/discover": "Discover MCP server",
      "initialize": "Initialize MCP connection",
      "tools/list": "List tools",
      "tools/call": toolName ? `Call tool · ${toolName}` : "Call tool",
    };
    return labels[method] ?? method;
  }

  const url = event.eventUrl ?? "";
  if (url.includes("oauth-protected-resource")) return "Discover protected resource";
  if (url.includes("oauth-authorization-server") || url.includes("openid-configuration")) {
    return "Discover authorization server";
  }
  if (url.includes("/token")) return "Exchange authorization token";
  return `${event.httpMethod ?? "HTTP"} request`;
}

function compactUrl(value?: string) {
  if (!value) return "";
  try {
    const url = new URL(value);
    return `${url.host}${url.pathname}`;
  } catch {
    return value;
  }
}

function milestoneTitle(event: InspectorEvent) {
  const labels: Record<string, string> = {
    "connection.connecting": "Connection started",
    "connection.connected": "MCP connection ready",
    "connection.failed": "Connection failed",
    "connection.closed": "Connection closed",
    "oauth.challenge": "Authorization challenge received",
    "oauth.authorization_redirect": "Authorization redirect prepared",
    "oauth.authorization_required": "User authorization required",
    "oauth.authorization_callback": "Authorization callback received",
    "oauth.token_acquired": "Access token acquired",
    "tools.list_failed": "Tool discovery failed",
    "tools.call_failed": "Tool call failed",
    "client.error": "Client transport error",
  };
  return labels[event.eventType] ?? event.eventType;
}

function visualCategory(events: InspectorEvent[]) {
  const request = events.find((event) => event.eventType === "http.request");
  if (events.some((event) => event.eventType.endsWith(".failed") || event.eventType === "client.error" ||
      (event.statusCode !== undefined && event.statusCode >= 400 && event.statusCode !== 401))) {
    return "errors" as const;
  }
  if (request && eventHeader(request, "mcp-method")) return "mcp" as const;
  if (events.some((event) => event.eventType.startsWith("oauth.") ||
      event.eventTarget === "authorization_server" || event.eventTarget === "user_agent")) {
    return "oauth" as const;
  }
  if (events.some((event) => event.eventType.startsWith("mcp."))) return "mcp" as const;
  return "http" as const;
}

function groupEvents(events: InspectorEvent[]): EventGroup[] {
  const rawGroups: { kind: EventGroup["kind"]; events: InspectorEvent[] }[] = [];
  let exchange: { kind: EventGroup["kind"]; events: InspectorEvent[] } | null = null;

  for (const event of events) {
    if (event.eventType === "http.request") {
      exchange = { kind: "exchange", events: [event] };
      rawGroups.push(exchange);
      continue;
    }
    if (exchange && ["http.response", "http.body", "mcp.message", "client.error"].includes(event.eventType)) {
      exchange.events.push(event);
      continue;
    }
    if (exchange && ["tools.list_failed", "tools.call_failed"].includes(event.eventType)) {
      exchange.events.push(event);
      exchange = null;
      continue;
    }
    exchange = null;
    rawGroups.push({ kind: "milestone", events: [event] });
  }

  return rawGroups.map((group, index) => {
    const first = group.events[0];
    const response = [...group.events].reverse().find((event) => event.eventType === "http.response");
    return {
      id: first.sequence,
      kind: group.kind,
      events: group.events,
      title: group.kind === "exchange" ? requestTitle(first) : milestoneTitle(first),
      subtitle: group.kind === "exchange"
        ? compactUrl(first.eventUrl)
        : first.eventMessage ?? first.eventTarget,
      category: visualCategory(group.events),
      statusCode: response?.statusCode,
    };
  });
}

function formattedBody(body: string) {
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function formatDuration(start: string, end: string) {
  const elapsed = new Date(end).valueOf() - new Date(start).valueOf();
  if (!Number.isFinite(elapsed) || elapsed <= 0) return "";
  if (elapsed < 1000) return `${elapsed} ms`;
  return `${(elapsed / 1000).toFixed(elapsed < 10000 ? 1 : 0)} s`;
}

function targetLabel(target: string) {
  const labels: Record<string, string> = {
    mcp_server: "MCP server",
    authorization_server: "Authorization server",
    protected_resource: "Protected resource",
    user_agent: "Browser",
    inspector: "Inspector",
  };
  return labels[target] ?? target.replaceAll("_", " ");
}

function eventLabel(event: InspectorEvent) {
  const labels: Record<string, string> = {
    "http.request": "Request sent",
    "http.response": "Response received",
    "http.body": "Response body read",
    "mcp.message": "MCP message decoded",
    "oauth.challenge": "Authorization challenge",
    "oauth.authorization_redirect": "Authorization redirect",
    "oauth.authorization_required": "User authorization needed",
    "oauth.authorization_callback": "Authorization callback",
    "oauth.token_acquired": "Access token acquired",
    "client.error": "Transport error",
    "connection.connecting": "Connection started",
    "connection.connected": "Connection ready",
    "connection.failed": "Connection failed",
    "connection.closed": "Connection closed",
    "tools.list_failed": "Tool discovery failed",
    "tools.call_failed": "Tool call failed",
  };
  return labels[event.eventType] ?? event.eventType.replaceAll(".", " ");
}

function eventNarrative(event: InspectorEvent) {
  if (event.eventMessage) return event.eventMessage;
  const body = parsedEventBody(event);
  if (event.eventType === "http.request") {
    return `${event.httpMethod ?? "HTTP"} request to ${targetLabel(event.eventTarget)}`;
  }
  if (event.eventType === "http.response") {
    return event.statusCode
      ? `${targetLabel(event.eventTarget)} returned HTTP ${event.statusCode}`
      : `Response received from ${targetLabel(event.eventTarget)}`;
  }
  if (event.eventType === "http.body") return `Response content received from ${targetLabel(event.eventTarget)}`;
  if (event.eventType === "mcp.message") {
    if (typeof body?.method === "string") return `Decoded ${body.method} message`;
    if (body?.error) return "Decoded an MCP error response";
    if (body?.result !== undefined) return "Decoded an MCP result";
    return "Decoded the MCP protocol message";
  }
  return `Client activity involving ${targetLabel(event.eventTarget)}`;
}

type OutcomeTone = "success" | "warning" | "danger" | "pending" | "neutral";

function activityOutcome(group: EventGroup): { label: string; tone: OutcomeTone } {
  if (group.statusCode === 401) return { label: "Authorization required", tone: "warning" };
  if (group.category === "errors" || (group.statusCode !== undefined && group.statusCode >= 400)) {
    return { label: group.statusCode ? `HTTP ${group.statusCode}` : "Failed", tone: "danger" };
  }
  if (group.statusCode !== undefined) return { label: `HTTP ${group.statusCode}`, tone: "success" };
  const type = group.events[group.events.length - 1].eventType;
  if (["connection.connected", "oauth.token_acquired"].includes(type)) return { label: "Completed", tone: "success" };
  if (["oauth.authorization_required", "oauth.authorization_redirect", "oauth.challenge"].includes(type)) {
    return { label: "Action needed", tone: "warning" };
  }
  if (type === "connection.connecting" || group.kind === "exchange") return { label: "In progress", tone: "pending" };
  if (type === "connection.closed") return { label: "Closed", tone: "neutral" };
  return { label: "Recorded", tone: "neutral" };
}

function ActivityGlyph({ group }: { group: EventGroup }) {
  if (group.category === "errors") return <CircleAlert size={17} />;
  if (group.category === "oauth") return <KeyRound size={17} />;
  if (group.category === "mcp") return <Braces size={17} />;
  if (group.events.some((event) => event.eventType === "connection.connected")) return <Check size={17} />;
  return <Send size={16} />;
}

function defaultArguments(tool: McpTool) {
  const schema = tool.inputSchema;
  if (!schema || typeof schema !== "object") return "{}";
  const properties = schema.properties as Record<string, Record<string, unknown>> | undefined;
  const required = Array.isArray(schema.required) ? (schema.required as string[]) : [];
  if (!properties || required.length === 0) return "{}";

  const result: Record<string, unknown> = {};
  for (const name of required) {
    const property = properties[name] ?? {};
    switch (property.type) {
      case "string":
        result[name] = "";
        break;
      case "number":
      case "integer":
        result[name] = 0;
        break;
      case "boolean":
        result[name] = false;
        break;
      case "array":
        result[name] = [];
        break;
      default:
        result[name] = {};
    }
  }
  return JSON.stringify(result, null, 2);
}

export default function App() {
  const [sessionId] = useState(getBrowserSessionId);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [connectionId, setConnectionIdState] = useState(() => localStorage.getItem(CONNECTION_KEY) ?? "");
  const [connections, setConnections] = useState<ConnectionStatus[]>([]);
  const [status, setStatus] = useState<ConnectionStatus | null>(null);
  const [events, setEvents] = useState<InspectorEvent[]>([]);
  const [streamOnline, setStreamOnline] = useState(false);
  const [authorizationUrl, setAuthorizationUrl] = useState("");
  const [view, setView] = useState<View>("events");
  const [eventFilter, setEventFilter] = useState<EventFilter>("all");
  const [search, setSearch] = useState("");
  const [form, setForm] = useState<ConnectionForm>(initialForm);
  const [showForm, setShowForm] = useState(!connectionId);
  const [submitting, setSubmitting] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [tools, setTools] = useState<McpTool[]>([]);
  const [toolsLoading, setToolsLoading] = useState(false);
  const [toolsError, setToolsError] = useState<string | null>(null);
  const [selectedTool, setSelectedTool] = useState<McpTool | null>(null);
  const [argumentsText, setArgumentsText] = useState("{}");
  const [toolResult, setToolResult] = useState<unknown>(null);
  const [callingTool, setCallingTool] = useState(false);

  useLayoutEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  const setConnectionId = useCallback((value: string) => {
    setConnectionIdState(value);
    if (value) localStorage.setItem(CONNECTION_KEY, value);
    else localStorage.removeItem(CONNECTION_KEY);
  }, []);

  const refreshConnections = useCallback(async () => {
    try {
      const result = await api.listConnections(sessionId);
      setConnections(result);
      return result;
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not load connections");
      return [];
    }
  }, [sessionId]);

  useEffect(() => {
    void refreshConnections();
  }, [refreshConnections]);

  useEffect(() => {
    if (!connectionId) {
      setStatus(null);
      return;
    }

    let disposed = false;
    const loadStatus = async () => {
      try {
        const next = await api.getConnection(sessionId, connectionId);
        if (!disposed) setStatus(next);
      } catch (error) {
        if (disposed) return;
        const message = error instanceof Error ? error.message : "Could not load connection";
        if (message.toLowerCase().includes("not found")) {
          setConnectionId("");
          setStatus(null);
          setShowForm(true);
          void refreshConnections();
        } else {
          setNotice(message);
        }
      }
    };

    void loadStatus();
    const timer = window.setInterval(loadStatus, 1800);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [connectionId, refreshConnections, sessionId, setConnectionId]);

  useEffect(() => {
    if (!connectionId) return;
    let disposed = false;
    let source: EventSource | null = null;
    let reconnectTimer = 0;
    let lastSequence = 0;

    const receive = (message: MessageEvent<string>) => {
      try {
        const event = JSON.parse(message.data) as InspectorEvent;
        lastSequence = Math.max(lastSequence, event.sequence);
        setEvents((current) => {
          if (current.some((item) => item.sequence === event.sequence)) return current;
          return [...current, event].sort((a, b) => a.sequence - b.sequence);
        });
        if (event.authorizationUrl) setAuthorizationUrl(event.authorizationUrl);
        const stateByEvent: Partial<Record<string, ConnectionState>> = {
          "connection.connecting": "connecting",
          "oauth.authorization_required": "awaiting_authorization",
          "connection.connected": "connected",
          "connection.failed": "failed",
          "connection.closed": "closed",
          "oauth.token_acquired": "connected",
          "tools.list_failed": "connected",
          "tools.call_failed": "connected",
        };
        const nextState = stateByEvent[event.eventType];
        if (nextState) {
          setStatus((current) => current ? {
            ...current,
            state: nextState,
            errorMessage: nextState === "failed" ? event.eventMessage : undefined,
          } : current);
        }
        if (["oauth.token_acquired", "tools.list_failed", "tools.call_failed"].includes(event.eventType)) {
          setAuthorizationUrl("");
        }
        if (event.eventType === "connection.closed") {
          source?.close();
          setStreamOnline(false);
        }
      } catch {
        setNotice("Received an unreadable event from the backend");
      }
    };

    const connect = () => {
      if (disposed) return;
      source = new EventSource(api.eventStreamUrl(sessionId, connectionId, lastSequence));
      for (const eventType of EVENT_TYPES) source.addEventListener(eventType, receive as EventListener);
      source.onopen = () => setStreamOnline(true);
      source.onerror = () => {
        setStreamOnline(false);
        source?.close();
        if (!disposed) reconnectTimer = window.setTimeout(connect, 1400);
      };
    };

    connect();
    return () => {
      disposed = true;
      source?.close();
      window.clearTimeout(reconnectTimer);
      setStreamOnline(false);
    };
  }, [connectionId, sessionId]);

  const loadTools = useCallback(async () => {
    if (!connectionId || status?.state !== "connected") return;
    setToolsLoading(true);
    setToolsError(null);
    try {
      const result = await api.listTools(sessionId, connectionId);
      setTools(result.tools ?? []);
      if (selectedTool) {
        setSelectedTool(result.tools.find((tool) => tool.name === selectedTool.name) ?? null);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "Could not load tools";
      setTools([]);
      setToolsError(message);
      setNotice(message);
    } finally {
      setToolsLoading(false);
    }
  }, [connectionId, selectedTool, sessionId, status?.state]);

  const connectionInfoKnown = status?.connectionInfo !== undefined;
  const toolsAdvertised = Boolean(status?.connectionInfo &&
    Object.prototype.hasOwnProperty.call(status.connectionInfo.capabilities, "tools"));

  useEffect(() => {
    if (status?.state !== "connected" || !connectionInfoKnown) return;
    if (toolsAdvertised) {
      void loadTools();
    } else {
      setTools([]);
      setToolsError(null);
    }
  }, [connectionInfoKnown, status?.state, toolsAdvertised]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectConnection = (id: string) => {
    if (id === connectionId) return;
    setConnectionId(id);
    setEvents([]);
    setTools([]);
    setToolsError(null);
    setSelectedTool(null);
    setToolResult(null);
    setAuthorizationUrl("");
    setShowForm(false);
    setNotice(null);
  };

  const createConnection = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setNotice(null);
    const scopes = form.scopes.split(/[\s,]+/).map((scope) => scope.trim()).filter(Boolean);
    let auth: AuthConfig;
    if (form.authType === "authorization_code") {
      const clientAuth = form.tokenAuthMethod === "none"
        ? { authMethod: "none" as const }
        : form.tokenAuthMethod === "private_key_jwt"
          ? privateKeyJwtConfig(form)
          : { authMethod: form.tokenAuthMethod, clientSecret: form.clientSecret };
      auth = {
        authType: "authorization_code",
        clientId: form.clientId,
        issuer: form.issuer,
        redirectUri: form.redirectUri,
        clientAuth,
        scopes,
      };
    } else if (form.authType === "cimd_authorization_code") {
      auth = {
        authType: "cimd_authorization_code",
        url: form.cimdUrl,
        redirectUri: form.redirectUri,
        clientAuth: form.tokenAuthMethod === "private_key_jwt"
          ? privateKeyJwtConfig(form)
          : { authMethod: "none" },
        scopes,
      };
    } else if (form.authType === "client_credentials") {
      auth = {
        authType: "client_credentials",
        clientId: form.clientId,
        issuer: form.issuer,
        clientAuth: form.tokenAuthMethod === "private_key_jwt"
          ? privateKeyJwtConfig(form)
          : {
              authMethod: form.tokenAuthMethod === "client_secret_post"
                ? "client_secret_post"
                : "client_secret_basic",
              clientSecret: form.clientSecret,
            },
        scopes,
      };
    } else if (form.authType === "cimd_client_credentials") {
      auth = {
        authType: "cimd_client_credentials",
        url: form.cimdUrl,
        clientAuth: privateKeyJwtConfig(form),
        scopes,
      };
    } else {
      auth = { authType: "none" };
    }

    const request: CreateConnectionRequest = {
      serverUrl: form.serverUrl,
      protocolMode: form.protocolMode,
      auth,
    };

    try {
      const result = await api.createConnection(sessionId, request);
      setConnectionId(result.connectionId);
      setStatus({
        connectionId: result.connectionId,
        serverUrl: form.serverUrl,
        state: result.state,
      });
      setEvents([]);
      setTools([]);
      setToolsError(null);
      setAuthorizationUrl("");
      setShowForm(false);
      await refreshConnections();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not create the connection");
    } finally {
      setForm(clearedSecrets);
      setSubmitting(false);
    }
  };

  const disconnect = async () => {
    if (!connectionId) return;
    setNotice(null);
    try {
      await api.disconnect(sessionId, connectionId);
      setConnectionId("");
      setStatus(null);
      setTools([]);
      setToolsError(null);
      setSelectedTool(null);
      setShowForm(true);
      await refreshConnections();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not close the connection");
    }
  };

  const chooseTool = (tool: McpTool) => {
    setSelectedTool(tool);
    setArgumentsText(defaultArguments(tool));
    setToolResult(null);
  };

  const callTool = async () => {
    if (!connectionId || !selectedTool) return;
    setNotice(null);
    let parsed: Record<string, unknown>;
    try {
      const value = JSON.parse(argumentsText) as unknown;
      if (!value || Array.isArray(value) || typeof value !== "object") {
        throw new Error("Arguments must be a JSON object");
      }
      parsed = value as Record<string, unknown>;
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Arguments are not valid JSON");
      return;
    }

    setCallingTool(true);
    try {
      setToolResult(await api.callTool(sessionId, connectionId, selectedTool.name, parsed));
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Tool invocation failed");
    } finally {
      setCallingTool(false);
    }
  };

  const connected = status?.state === "connected";

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div>
            <strong>MCP Inspector</strong>
            <span>Configure, test, and observe MCP clients</span>
          </div>
        </div>
        <div className="topbar-actions">
          <button
            className="theme-toggle"
            type="button"
            onClick={() => setTheme((current) => current === "light" ? "dark" : "light")}
            title={`Switch to ${theme === "light" ? "dark" : "light"} theme`}
            aria-label={`Switch to ${theme === "light" ? "dark" : "light"} theme`}
          >
            {theme === "light" ? <Moon size={16} /> : <Sun size={16} />}
          </button>
          <div className="session-chip" title={sessionId}>
            <KeyRound size={14} /> Session {shortId(sessionId)}
          </div>
        </div>
      </header>

      {notice && (
        <div className="notice" role="alert">
          <CircleAlert size={17} />
          <span>{notice}</span>
          <button onClick={() => setNotice(null)} aria-label="Dismiss"><X size={16} /></button>
        </div>
      )}

      <main className="workspace">
        <aside className="sidebar">
          <div className="sidebar-heading">
            <div>
              <span className="eyebrow">Workspace</span>
              <h2>Connections</h2>
            </div>
            <button className="icon-button" onClick={() => setShowForm(true)} title="New connection">
              <Plus size={18} />
            </button>
          </div>

          <div className="connection-list">
            {connections.length === 0 && <p className="muted compact">No active connections yet.</p>}
            {connections.map((connection) => (
              <button
                key={connection.connectionId}
                className={`connection-item ${connection.connectionId === connectionId ? "active" : ""}`}
                onClick={() => selectConnection(connection.connectionId)}
              >
                <span className={`state-dot ${connection.state}`} />
                <span className="connection-copy">
                  <strong>{new URL(connection.serverUrl).host || connection.serverUrl}</strong>
                  <small>{stateLabels[connection.state]}</small>
                </span>
                <ChevronRight size={16} />
              </button>
            ))}
          </div>

          <div className="sidebar-foot">
            <span>Ephemeral mode</span>
            <small>Connections reset with the backend</small>
          </div>
        </aside>

        <section className="content">
          {showForm ? (
            <ConnectionPanel
              form={form}
              setForm={setForm}
              submitting={submitting}
              onSubmit={createConnection}
              onCancel={connectionId ? () => setShowForm(false) : undefined}
            />
          ) : status ? (
            <>
              <section className="connection-hero">
                <div className="hero-main">
                  <div className={`hero-icon ${status.state}`}><Server size={22} /></div>
                  <div>
                    <div className="hero-title-row">
                      <h1>{status.serverUrl}</h1>
                      <span className={`status-pill ${status.state}`}>
                        {status.state === "connecting" && <Loader2 className="spin" size={13} />}
                        {status.state === "connected" && <Check size={13} />}
                        {stateLabels[status.state]}
                      </span>
                    </div>
                    <p>
                      {shortId(status.connectionId)} · {events.length} captured events
                      {status.connectionInfo?.protocolVersion && ` · MCP ${status.connectionInfo.protocolVersion}`}
                    </p>
                  </div>
                </div>
                <div className="hero-actions">
                  <span className={`stream-indicator ${streamOnline ? "online" : ""}`}>
                    <Radio size={14} /> {streamOnline ? "Live" : "Reconnecting"}
                  </span>
                  <button className="secondary-button danger" onClick={disconnect}>
                    <Power size={15} /> Disconnect
                  </button>
                </div>
              </section>

              {status.errorMessage && (
                <div className="inline-alert"><CircleAlert size={17} /> {status.errorMessage}</div>
              )}

              {authorizationUrl && status.state === "awaiting_authorization" && (
                <div className="authorization-banner">
                  <div className="auth-icon"><KeyRound size={20} /></div>
                  <div>
                    <strong>Authorization is required</strong>
                    <p>Continue in the provider window. This inspector never stores the returned code or token.</p>
                  </div>
                  <a className="primary-button" href={authorizationUrl} target="_blank" rel="noreferrer">
                    Authorize <ExternalLink size={15} />
                  </a>
                </div>
              )}

              <nav className="view-tabs">
                <button className={view === "events" ? "active" : ""} onClick={() => setView("events")}>
                  <TerminalSquare size={16} /> Event log <span>{events.length}</span>
                </button>
                <button className={view === "tools" ? "active" : ""} onClick={() => setView("tools")}>
                  <Wrench size={16} /> Tools <span>{tools.length}</span>
                </button>
              </nav>

              {view === "events" ? (
                <EventLog
                  events={events}
                  total={events.length}
                  filter={eventFilter}
                  search={search}
                  onFilter={setEventFilter}
                  onSearch={setSearch}
                  onClear={() => setEvents([])}
                />
              ) : (
                <ToolsPanel
                  connected={connected}
                  tools={tools}
                  loading={toolsLoading}
                  error={toolsError}
                  capabilityKnown={connectionInfoKnown}
                  toolsAdvertised={toolsAdvertised}
                  protocolVersion={status.connectionInfo?.protocolVersion}
                  selected={selectedTool}
                  argumentsText={argumentsText}
                  result={toolResult}
                  calling={callingTool}
                  onRefresh={loadTools}
                  onSelect={chooseTool}
                  onArguments={setArgumentsText}
                  onCall={callTool}
                />
              )}
            </>
          ) : (
            <div className="empty-state">
              <div><CircleOff size={30} /></div>
              <h1>No active connection</h1>
              <p>Configure an MCP server to inspect its transport, authorization flow, and tools.</p>
              <button className="primary-button" onClick={() => setShowForm(true)}><Plus size={16} /> New connection</button>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

function ConnectionPanel({
  form,
  setForm,
  submitting,
  onSubmit,
  onCancel,
}: {
  form: ConnectionForm;
  setForm: React.Dispatch<React.SetStateAction<ConnectionForm>>;
  submitting: boolean;
  onSubmit: (event: FormEvent) => void;
  onCancel?: () => void;
}) {
  const [editingCimdUrl, setEditingCimdUrl] = useState(false);
  const update = <K extends keyof ConnectionForm>(key: K, value: ConnectionForm[K]) =>
    setForm((current) => ({ ...current, [key]: value }));

  const selectAuthType = (authType: AuthType) => {
    const tokenAuthMethod: TokenAuthMethod = authType === "authorization_code" ||
      authType === "cimd_authorization_code"
      ? "none"
      : authType === "cimd_client_credentials"
        ? "private_key_jwt"
        : authType === "client_credentials"
          ? "client_secret_basic"
          : "none";
    setForm((current) => ({
      ...current,
      authType,
      tokenAuthMethod,
      redirectUri: authType === "cimd_authorization_code"
        ? CIMD_CALLBACK_URL
        : current.authType === "cimd_authorization_code"
          ? STANDARD_CALLBACK_URL
          : current.redirectUri,
    }));
    if (authType === "cimd_authorization_code" || authType === "cimd_client_credentials") {
      setEditingCimdUrl(false);
    }
  };

  const isCimd = form.authType === "cimd_authorization_code" ||
    form.authType === "cimd_client_credentials";
  const isAuthorizationCode = form.authType === "authorization_code" ||
    form.authType === "cimd_authorization_code";
  const usesPrivateKeyJwt = form.tokenAuthMethod === "private_key_jwt";

  return (
    <div className="setup-wrap">
      <div className="setup-intro">
        <span className="eyebrow">New inspection</span>
        <h1>Connect to an MCP server</h1>
        <p>Configure the Ballerina client, follow every protocol exchange, and exercise tools from one workspace.</p>
      </div>

      <form className="setup-card" onSubmit={onSubmit}>
        <div className="form-section-heading">
          <div className="section-number">01</div>
          <div><h3>Server</h3><p>Where should the inspector connect?</p></div>
        </div>
        <div className="field-grid two-one">
          <label className="field">
            <span>Server URL</span>
            <div className="input-with-icon"><Server size={16} /><input type="url" required value={form.serverUrl} onChange={(e) => update("serverUrl", e.target.value)} placeholder="https://example.com/mcp" /></div>
          </label>
          <label className="field">
            <span>Protocol</span>
            <select value={form.protocolMode} onChange={(e) => update("protocolMode", e.target.value as ProtocolMode)}>
              <option value="auto">Auto detect</option>
              <option value="modern">Modern only</option>
              <option value="legacy">Legacy only</option>
            </select>
          </label>
        </div>

        <div className="form-divider" />
        <div className="form-section-heading">
          <div className="section-number">02</div>
          <div><h3>Authorization</h3><p>Secrets are discarded from the browser after submission.</p></div>
        </div>
        <div className="auth-options">
          {([
            ["none", "No auth", "Connect directly"],
            ["authorization_code", "Auth code", "Pre-registered OAuth"],
            ["client_credentials", "Client credentials", "Pre-registered OAuth"],
            ["cimd_authorization_code", "CIMD auth code", "Metadata client"],
            ["cimd_client_credentials", "CIMD credentials", "Metadata + private key"],
          ] as const).map(([value, label, hint]) => (
            <button type="button" key={value} className={form.authType === value ? "active" : ""} onClick={() => selectAuthType(value)}>
              <span className="radio-mark">{form.authType === value && <CircleDot size={14} />}</span>
              <span><strong>{label}</strong><small>{hint}</small></span>
            </button>
          ))}
        </div>

        {form.authType !== "none" && (
          <div className="oauth-fields">
            {isCimd ? (
              <>
                <div className="cimd-note">
                  <div><Braces size={17} /></div>
                  <span>
                    <strong>The metadata URL is the OAuth client ID</strong>
                    <small>{form.authType === "cimd_client_credentials" ? "Client credentials requires private_key_jwt." : "Authorization code may be public or use private_key_jwt."}</small>
                  </span>
                </div>
                <label className="field">
                  <span>
                    Client ID Metadata Document
                    <button className="field-edit" type="button" onClick={() => setEditingCimdUrl((value) => !value)}>
                      {editingCimdUrl ? <LockKeyhole size={12} /> : <Pencil size={12} />}
                      {editingCimdUrl ? "Lock" : "Edit"}
                    </button>
                  </span>
                  <div className={`input-with-icon ${editingCimdUrl ? "editing" : "locked"}`}>
                    {editingCimdUrl ? <Pencil size={15} /> : <LockKeyhole size={15} />}
                    <input type="url" required readOnly={!editingCimdUrl} value={form.cimdUrl} onChange={(event) => update("cimdUrl", event.target.value)} />
                  </div>
                </label>
              </>
            ) : (
              <div className="field-grid">
                <label className="field"><span>Issuer</span><input type="url" required value={form.issuer} onChange={(e) => update("issuer", e.target.value)} placeholder="https://auth.example.com" /></label>
                <label className="field"><span>Client ID</span><input required value={form.clientId} onChange={(e) => update("clientId", e.target.value)} placeholder="mcp-inspector" autoComplete="off" /></label>
              </div>
            )}

            {isAuthorizationCode && (
              <label className="field"><span>Redirect URI {isCimd && <em>must appear in the metadata document</em>}</span><input type="url" required value={form.redirectUri} onChange={(e) => update("redirectUri", e.target.value)} /></label>
            )}

            <label className="field">
              <span>Token endpoint authentication</span>
              <select
                value={form.tokenAuthMethod}
                disabled={form.authType === "cimd_client_credentials"}
                onChange={(event) => update("tokenAuthMethod", event.target.value as TokenAuthMethod)}
              >
                {isAuthorizationCode && <option value="none">None (public client)</option>}
                {!isCimd && <option value="client_secret_basic">Client secret — HTTP Basic</option>}
                {!isCimd && <option value="client_secret_post">Client secret — request body</option>}
                <option value="private_key_jwt">Private key JWT</option>
              </select>
            </label>

            {(form.tokenAuthMethod === "client_secret_basic" || form.tokenAuthMethod === "client_secret_post") && (
              <label className="field"><span>Client secret</span><input type="password" required value={form.clientSecret} onChange={(e) => update("clientSecret", e.target.value)} placeholder="Not persisted" autoComplete="new-password" /></label>
            )}

            {usesPrivateKeyJwt && (
              <div className="signing-fields">
                <div className="signing-heading"><KeyRound size={16} /><span><strong>Private key JWT</strong><small>RSA keys only. File paths are resolved on the backend host.</small></span></div>
                <div className="field-grid">
                  <label className="field"><span>Signing algorithm</span><select value={form.signingAlgorithm} onChange={(event) => update("signingAlgorithm", event.target.value as RsaSigningAlgorithm)}><option value="RS256">RS256</option><option value="RS384">RS384</option><option value="RS512">RS512</option></select></label>
                  <label className="field"><span>Key ID <em>optional</em></span><input value={form.keyId} onChange={(event) => update("keyId", event.target.value)} placeholder="mcp-signing-1" /></label>
                </div>
                <label className="field"><span>Key source</span><select value={form.keySourceType} onChange={(event) => update("keySourceType", event.target.value as KeySourceType)}><option value="key_file">Private-key file</option><option value="key_store">Key store</option></select></label>
                {form.keySourceType === "key_file" ? (
                  <div className="field-grid">
                    <label className="field"><span>Private-key file</span><input required value={form.keyFilePath} onChange={(event) => update("keyFilePath", event.target.value)} placeholder="C:\\keys\\client-private.pem" /></label>
                    <label className="field"><span>Key password <em>optional</em></span><input type="password" value={form.keyFilePassword} onChange={(event) => update("keyFilePassword", event.target.value)} autoComplete="new-password" /></label>
                  </div>
                ) : (
                  <>
                    <div className="field-grid">
                      <label className="field"><span>Key-store path</span><input required value={form.keyStorePath} onChange={(event) => update("keyStorePath", event.target.value)} placeholder="C:\\keys\\client.p12" /></label>
                      <label className="field"><span>Key-store password</span><input type="password" required value={form.keyStorePassword} onChange={(event) => update("keyStorePassword", event.target.value)} autoComplete="new-password" /></label>
                    </div>
                    <div className="field-grid">
                      <label className="field"><span>Key alias</span><input required value={form.keyAlias} onChange={(event) => update("keyAlias", event.target.value)} /></label>
                      <label className="field"><span>Private-key password</span><input type="password" required value={form.keyPassword} onChange={(event) => update("keyPassword", event.target.value)} autoComplete="new-password" /></label>
                    </div>
                  </>
                )}
              </div>
            )}

            <label className="field"><span>Scopes <em>optional, separated by spaces or commas</em></span><input value={form.scopes} onChange={(e) => update("scopes", e.target.value)} placeholder="openid profile tools.read" /></label>
          </div>
        )}

        <div className="form-actions">
          {onCancel && <button className="secondary-button" type="button" onClick={onCancel}>Cancel</button>}
          <button className="primary-button" disabled={submitting}>
            {submitting ? <Loader2 className="spin" size={16} /> : <ArrowRight size={16} />}
            {submitting ? "Creating connection" : "Connect and inspect"}
          </button>
        </div>
      </form>
    </div>
  );
}

function EventLog({ events, total, filter, search, onFilter, onSearch, onClear }: {
  events: InspectorEvent[];
  total: number;
  filter: EventFilter;
  search: string;
  onFilter: (value: EventFilter) => void;
  onSearch: (value: string) => void;
  onClear: () => void;
}) {
  const eventListRef = useRef<HTMLDivElement>(null);
  const [following, setFollowing] = useState(true);
  const filters: { value: EventFilter; label: string }[] = [
    { value: "all", label: "All" }, { value: "http", label: "HTTP" },
    { value: "mcp", label: "MCP" }, { value: "oauth", label: "OAuth" },
    { value: "errors", label: "Errors" },
  ];
  const groups = useMemo(() => groupEvents(events), [events]);
  const filterCounts = useMemo(() => ({
    all: groups.length,
    http: groups.filter((group) => groupMatchesFilter(group, "http")).length,
    mcp: groups.filter((group) => groupMatchesFilter(group, "mcp")).length,
    oauth: groups.filter((group) => groupMatchesFilter(group, "oauth")).length,
    errors: groups.filter((group) => groupMatchesFilter(group, "errors")).length,
  }), [groups]);
  const query = search.trim().toLowerCase();
  const visibleGroups = groups.filter((group) => {
    const matchesFilter = groupMatchesFilter(group, filter);
    const matchesSearch = !query || group.title.toLowerCase().includes(query) ||
      group.subtitle.toLowerCase().includes(query) ||
      group.events.some((event) => JSON.stringify(event).toLowerCase().includes(query));
    return matchesFilter && matchesSearch;
  });

  const jumpToLatest = useCallback((behavior: ScrollBehavior = "smooth") => {
    const list = eventListRef.current;
    if (!list) return;
    list.scrollTo({ top: list.scrollHeight, behavior });
    setFollowing(true);
  }, []);

  useEffect(() => {
    if (!following) return;
    const frame = window.requestAnimationFrame(() => jumpToLatest("auto"));
    return () => window.cancelAnimationFrame(frame);
  }, [following, jumpToLatest, total, visibleGroups.length]);

  const trackScrollPosition = () => {
    const list = eventListRef.current;
    if (!list) return;
    setFollowing(list.scrollHeight - list.scrollTop - list.clientHeight < 48);
  };

  return (
    <section className="panel log-panel">
      <div className="panel-toolbar">
        <div className="filter-group"><ListFilter size={15} />{filters.map((item) => <button key={item.value} className={filter === item.value ? "active" : ""} onClick={() => onFilter(item.value)}>{item.label}<span>{filterCounts[item.value]}</span></button>)}</div>
        <div className="toolbar-actions">
          <button className={`tail-button ${following ? "active" : ""}`} onClick={() => jumpToLatest()} title="Follow the newest activity">
            <Radio size={13} /> {following ? "Following" : "Jump to latest"}
          </button>
          <label className="search-box"><Search size={15} /><input value={search} onChange={(e) => onSearch(e.target.value)} placeholder="Search events" /></label>
          <button className="icon-button" onClick={onClear} disabled={total === 0} title="Clear local event view"><Trash2 size={16} /></button>
        </div>
      </div>
      <div className="activity-overview">
        <div><strong>Connection activity</strong><span>Each entry is one operation. Expand it only when you need protocol details.</span></div>
        <span>{visibleGroups.length} of {groups.length} operations</span>
      </div>
      <div className="event-list" ref={eventListRef} onScroll={trackScrollPosition}>
        {visibleGroups.length === 0 ? (
          <div className="panel-empty"><Clock3 size={25} /><strong>No matching events</strong><span>New client activity will appear here in real time.</span></div>
        ) : visibleGroups.map((group) => <EventGroupRow key={group.id} group={group} />)}
      </div>
    </section>
  );
}

function EventGroupRow({ group }: { group: EventGroup }) {
  const [open, setOpen] = useState(false);
  const first = group.events[0];
  const last = group.events[group.events.length - 1];
  const request = group.events.find((event) => event.eventType === "http.request");
  const duration = formatDuration(first.timestamp, last.timestamp);
  const outcome = activityOutcome(group);
  const hasDetails = group.events.length > 1 || group.events.some((event) =>
    event.eventBody || Object.keys(event.eventHeaders ?? {}).length > 0 || event.authorizationUrl || event.eventMessage);
  const categoryLabel = group.category === "mcp" ? "MCP" :
    group.category === "oauth" ? "OAuth" : group.category === "errors" ? "Error" :
      group.kind === "milestone" ? "Lifecycle" : "HTTP";
  return (
    <article className={`activity-card ${group.category} ${open ? "open" : ""}`}>
      <button className="activity-summary" onClick={() => hasDetails && setOpen(!open)} aria-expanded={open}>
        <span className={`activity-glyph ${group.category}`}><ActivityGlyph group={group} /></span>
        <span className="activity-copy">
          <span className="activity-title">
            <strong>{group.title}</strong>
            <span className={`event-kind ${group.category}`}>{categoryLabel}</span>
          </span>
          <span className="activity-subtitle">{group.subtitle || targetLabel(first.eventTarget)}</span>
          <span className="activity-meta">
            {request?.httpMethod && <span>{request.httpMethod}</span>}
            <span>{targetLabel(first.eventTarget)}</span>
            {duration && <span>{duration}</span>}
          </span>
        </span>
        <span className="activity-result">
          <span className={`outcome ${outcome.tone}`}><CircleDot size={11} />{outcome.label}</span>
          <time>{formatTime(first.timestamp)}</time>
        </span>
        {hasDetails && <ChevronRight className={open ? "rotated" : ""} size={17} />}
      </button>
      {open && hasDetails && (
        <div className="activity-details">
          {request && (
            <div className="activity-route">
              <div><span>From</span><strong>Inspector client</strong></div>
              <ArrowRight size={17} />
              <div><span>To</span><strong>{targetLabel(request.eventTarget)}</strong></div>
              {duration && <div className="route-duration"><span>Duration</span><strong>{duration}</strong></div>}
            </div>
          )}
          <div className="technical-heading">
            <div><strong>Protocol details</strong><span>{group.events.length} observer {group.events.length === 1 ? "event" : "events"}</span></div>
            <small>Raw sequence {first.sequence}{first.sequence !== last.sequence ? `–${last.sequence}` : ""}</small>
          </div>
          {group.events.map((event) => (
            <div className={`protocol-step ${event.eventType.includes("error") || event.eventType.endsWith("failed") ? "failed" : ""}`} key={event.sequence}>
              <div className="protocol-rail"><span /></div>
              <div className="protocol-content">
                <div className="protocol-heading">
                  <div><strong>{eventLabel(event)}</strong><span>{eventNarrative(event)}</span></div>
                  <time>{formatTime(event.timestamp)}{event.statusCode ? ` · HTTP ${event.statusCode}` : ""}</time>
                </div>
                {event.authorizationUrl && <div className="event-payload prominent"><span>Continue authorization</span><a href={event.authorizationUrl} target="_blank" rel="noreferrer">{event.authorizationUrl}<ExternalLink size={12} /></a></div>}
                {event.eventBody && <div className="event-payload"><span>{event.eventType === "mcp.message" ? "Decoded message" : "Body"}</span><pre>{formattedBody(event.eventBody)}</pre></div>}
                {Object.keys(event.eventHeaders ?? {}).length > 0 && (
                  <details className="raw-disclosure">
                    <summary>Headers <span>{Object.keys(event.eventHeaders ?? {}).length}</span></summary>
                    <pre>{JSON.stringify(event.eventHeaders, null, 2)}</pre>
                  </details>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </article>
  );
}

function ToolsPanel({ connected, tools, loading, error, capabilityKnown, toolsAdvertised, protocolVersion, selected, argumentsText, result, calling, onRefresh, onSelect, onArguments, onCall }: {
  connected: boolean;
  tools: McpTool[];
  loading: boolean;
  error: string | null;
  capabilityKnown: boolean;
  toolsAdvertised: boolean;
  protocolVersion?: string;
  selected: McpTool | null;
  argumentsText: string;
  result: unknown;
  calling: boolean;
  onRefresh: () => void;
  onSelect: (tool: McpTool) => void;
  onArguments: (value: string) => void;
  onCall: () => void;
}) {
  if (!connected) return <div className="panel panel-empty tall"><Wrench size={28} /><strong>Waiting for a connection</strong><span>Tools become available after the MCP handshake completes.</span></div>;
  return (
    <section className="tools-layout">
      <div className="panel tool-list-panel">
        <div className="panel-title"><div><span className="eyebrow">Discovered</span><h3>Tools</h3></div><button className="icon-button" onClick={onRefresh} disabled={loading}><RefreshCw className={loading ? "spin" : ""} size={16} /></button></div>
        <div className="tool-list">
          {error && !loading && (
            <div className="panel-empty tool-error">
              <CircleAlert size={22} />
              <strong>tools/list failed</strong>
              <span>{error}</span>
              {error.toLowerCase().includes("modern tools/list") && (
                <small>This looks like an older response shape. Reconnect with “Legacy only” selected.</small>
              )}
              <button className="secondary-button" onClick={onRefresh}><RefreshCw size={14} /> Retry</button>
            </div>
          )}
          {!error && !loading && capabilityKnown && !toolsAdvertised && (
            <div className="panel-empty">
              <CircleOff size={22} />
              <strong>Tools capability not advertised</strong>
              <span>The MCP initialize response for {protocolVersion ?? "this connection"} did not declare a tools capability, so tools/list was not sent.</span>
            </div>
          )}
          {!error && !loading && toolsAdvertised && tools.length === 0 && (
            <div className="panel-empty"><CircleOff size={22} /><strong>No tools returned</strong><span>The server advertised tools, and the explicit tools/list request returned an empty list.</span></div>
          )}
          {!error && !loading && !capabilityKnown && (
            <div className="panel-empty"><Loader2 className="spin" size={22} /><span>Reading negotiated server capabilities…</span></div>
          )}
          {tools.map((tool) => <button key={tool.name} className={selected?.name === tool.name ? "active" : ""} onClick={() => onSelect(tool)}><span className="tool-icon"><Wrench size={15} /></span><span><strong>{tool.title ?? tool.name}</strong><small>{tool.description ?? "No description provided"}</small></span><ChevronRight size={15} /></button>)}
        </div>
      </div>
      <div className="panel tool-workbench">
        {!selected ? <div className="panel-empty tall"><Braces size={28} /><strong>Select a tool</strong><span>Review its schema, provide JSON arguments, and invoke it.</span></div> : <>
          <div className="tool-heading"><div><span className="eyebrow">Tool invocation</span><h2>{selected.title ?? selected.name}</h2><p>{selected.description}</p></div><span className="tool-name">{selected.name}</span></div>
          <div className="schema-block"><span>Input schema</span><pre>{JSON.stringify(selected.inputSchema ?? {}, null, 2)}</pre></div>
          <label className="editor-label"><span>Arguments</span><span>JSON object</span></label>
          <textarea className="json-editor" spellCheck={false} value={argumentsText} onChange={(e) => onArguments(e.target.value)} />
          <div className="invoke-row"><button className="primary-button" onClick={onCall} disabled={calling}>{calling ? <Loader2 className="spin" size={16} /> : <Send size={15} />}{calling ? "Invoking" : "Invoke tool"}</button></div>
          {result !== null && <div className="result-block"><div><span>Result</span><span className="success-label"><Check size={13} /> Completed</span></div><pre>{JSON.stringify(result, null, 2)}</pre></div>}
        </>}
      </div>
    </section>
  );
}
