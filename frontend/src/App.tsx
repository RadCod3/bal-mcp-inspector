import {
  ArrowLeftRight,
  Braces,
  Check,
  CircleAlert,
  CircleOff,
  ExternalLink,
  KeyRound,
  LockKeyhole,
  Loader2,
  Moon,
  Plus,
  Power,
  RefreshCw,
  Send,
  Server,
  Sun,
  Wrench,
  X,
} from "lucide-react";
import { FormEvent, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import { CodeBlock } from "./components/CodeBlock";
import { RequestLog } from "./components/RequestLog";
import { hostOf } from "./requests";
import { routePath, useRoute, type View } from "./router";
import type {
  AuthConfig,
  CimdProfile,
  CimdProfileInfo,
  ConnectionState,
  ConnectionStatus,
  CreateConnectionRequest,
  InspectorEvent,
  McpTool,
  ProtocolMode,
  SecretMethod,
} from "./types";

const SESSION_KEY = "balInspector.browserSessionId";
const CONNECTION_KEY = "balInspector.activeConnectionId";
const THEME_KEY = "balInspector.theme";
const MOD_KEY = /Mac|iPhone|iPad/.test(navigator.userAgent) ? "⌘" : "Ctrl";

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

interface ConnectionForm {
  serverUrl: string;
  protocolMode: ProtocolMode;
  authType: AuthType;
  clientId: string;
  clientSecret: string;
  issuer: string;
  redirectUri: string;
  scopes: string;
  tokenAuthMethod: SecretMethod;
  cimdProfile: CimdProfile;
}

// In dev, callbacks go straight to the local backend; in deployments, nginx proxies them from this origin.
const CALLBACK_ORIGIN = import.meta.env.DEV ? "http://localhost:8080" : window.location.origin;
const STANDARD_CALLBACK_URL = `${CALLBACK_ORIGIN}/api/v1/oauth/callback`;

const initialForm: ConnectionForm = {
  serverUrl: "http://localhost:9090/mcp",
  protocolMode: "auto",
  authType: "none",
  clientId: "",
  clientSecret: "",
  issuer: "",
  redirectUri: STANDARD_CALLBACK_URL,
  scopes: "",
  tokenAuthMethod: "client_secret_basic",
  cimdProfile: "none",
};

function clearedSecrets(form: ConnectionForm): ConnectionForm {
  return {
    ...form,
    clientSecret: "",
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
  const [route, navigate] = useRoute();
  const connectionId = route.page === "connection" ? route.connectionId : "";
  const view: View = route.page === "connection" ? route.view : "requests";
  const showForm = route.page === "new";
  const [connections, setConnections] = useState<ConnectionStatus[]>([]);
  const [status, setStatus] = useState<ConnectionStatus | null>(null);
  const [events, setEvents] = useState<InspectorEvent[]>([]);
  const [streamOnline, setStreamOnline] = useState(false);
  const [authorizationUrl, setAuthorizationUrl] = useState("");
  const [form, setForm] = useState<ConnectionForm>(initialForm);
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

  const openConnection = useCallback((id: string, options?: { replace?: boolean }) => {
    navigate({ page: "connection", connectionId: id, view: "requests" }, options);
  }, [navigate]);

  // "/" has no screen of its own: resume the last connection viewed in this browser, or start a new one.
  useEffect(() => {
    if (route.page !== "home") return;
    const lastConnectionId = localStorage.getItem(CONNECTION_KEY);
    if (lastConnectionId) openConnection(lastConnectionId, { replace: true });
    else navigate({ page: "new" }, { replace: true });
  }, [navigate, openConnection, route.page]);

  useEffect(() => {
    if (connectionId) localStorage.setItem(CONNECTION_KEY, connectionId);
  }, [connectionId]);

  // Everything below the sidebar belongs to one connection, so switching connections starts it fresh.
  useEffect(() => {
    setStatus((current) => current?.connectionId === connectionId ? current : null);
    setEvents([]);
    setTools([]);
    setToolsError(null);
    setSelectedTool(null);
    setToolResult(null);
    setAuthorizationUrl("");
  }, [connectionId]);

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
          // A stale link or a restarted backend: forget the connection and offer a new one.
          if (localStorage.getItem(CONNECTION_KEY) === connectionId) localStorage.removeItem(CONNECTION_KEY);
          setNotice(`Connection ${shortId(connectionId)} no longer exists. Connections are cleared when the backend restarts.`);
          navigate({ page: "new" }, { replace: true });
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
  }, [connectionId, navigate, refreshConnections, sessionId]);

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
    setNotice(null);
    openConnection(id);
  };

  const createConnection = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setNotice(null);
    const scopes = form.scopes.split(/[\s,]+/).map((scope) => scope.trim()).filter(Boolean);
    let auth: AuthConfig;
    if (form.authType === "authorization_code") {
      auth = {
        authType: "authorization_code",
        clientId: form.clientId,
        issuer: form.issuer,
        redirectUri: form.redirectUri,
        clientAuth: {authMethod: form.tokenAuthMethod, clientSecret: form.clientSecret},
        scopes,
      };
    } else if (form.authType === "cimd_authorization_code") {
      auth = {
        authType: "cimd_authorization_code",
        profile: form.cimdProfile,
        scopes,
      };
    } else if (form.authType === "client_credentials") {
      auth = {
        authType: "client_credentials",
        clientId: form.clientId,
        issuer: form.issuer,
        clientAuth: {authMethod: form.tokenAuthMethod, clientSecret: form.clientSecret},
        scopes,
      };
    } else if (form.authType === "cimd_client_credentials") {
      auth = {
        authType: "cimd_client_credentials",
        profile: form.cimdProfile === "none" ? "jwks" : form.cimdProfile,
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
      setStatus({
        connectionId: result.connectionId,
        serverUrl: form.serverUrl,
        state: result.state,
      });
      openConnection(result.connectionId);
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
      localStorage.removeItem(CONNECTION_KEY);
      navigate({ page: "new" });
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

  // Cancelling the form returns to the connection it was opened from, if that still exists.
  const lastConnectionId = showForm ? localStorage.getItem(CONNECTION_KEY) : null;
  const returnConnectionId = connections.some((connection) => connection.connectionId === lastConnectionId)
    ? lastConnectionId
    : null;

  const requestCount = useMemo(
    () => events.filter((event) => event.eventType === "http.request").length,
    [events],
  );
  const serverInfo = status?.connectionInfo?.serverInfo;

  return (
    <div className="app-shell">
      {notice && (
        <div className="notice" role="alert">
          <CircleAlert size={18} />
          <span>{notice}</span>
          <button onClick={() => setNotice(null)} aria-label="Dismiss"><X size={16} /></button>
        </div>
      )}

      <main className="workspace">
        <aside className="sidebar">
          <div className="brand">
            <strong>MCP Inspector</strong>
            <span>for the Ballerina MCP client</span>
          </div>

          <div className="sidebar-section">
            <div className="sidebar-heading">
              <h2>Connections</h2>
              <button className={`new-connection ${showForm ? "active" : ""}`} onClick={() => navigate({ page: "new" })}>
                <Plus size={15} /> New
              </button>
            </div>

            <div className="connection-list">
              {connections.length === 0 && <p className="sidebar-empty">Nothing connected yet.</p>}
              {connections.map((connection) => {
                // The list is fetched on demand, so prefer the live status for the active connection.
                const state = connection.connectionId === connectionId && status ? status.state : connection.state;
                return (
                  <a
                    key={connection.connectionId}
                    href={routePath({ page: "connection", connectionId: connection.connectionId, view: "requests" })}
                    className={`connection-item ${connection.connectionId === connectionId ? "active" : ""}`}
                    aria-current={connection.connectionId === connectionId ? "page" : undefined}
                    onClick={(event) => {
                      if (event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
                      event.preventDefault();
                      selectConnection(connection.connectionId);
                    }}
                    title={connection.serverUrl}
                  >
                    <span className={`state-dot ${state}`} />
                    <span className="connection-copy">
                      <strong>{hostOf(connection.serverUrl)}</strong>
                      <small>{stateLabels[state]}</small>
                    </span>
                  </a>
                );
              })}
            </div>
          </div>

          <div className="sidebar-foot">
            <p>Connections are kept in backend memory and cleared when it restarts.</p>
            <div className="sidebar-foot-row">
              <span className="session-id" title={`Browser session ${sessionId}`}>Session <code>{shortId(sessionId)}</code></span>
              <button
                className="icon-button"
                type="button"
                onClick={() => setTheme((current) => current === "light" ? "dark" : "light")}
                title={`Switch to ${theme === "light" ? "dark" : "light"} theme`}
                aria-label={`Switch to ${theme === "light" ? "dark" : "light"} theme`}
              >
                {theme === "light" ? <Moon size={16} /> : <Sun size={16} />}
              </button>
            </div>
          </div>
        </aside>

        <section className="content">
          {showForm ? (
            <ConnectionPanel
              form={form}
              setForm={setForm}
              submitting={submitting}
              onSubmit={createConnection}
              onCancel={returnConnectionId ? () => openConnection(returnConnectionId) : undefined}
            />
          ) : status ? (
            <div className="connection-view">
              <section className="connection-header">
                <div className="connection-heading">
                  <span className={`status-pill ${status.state}`}>
                    {status.state === "connecting" ? <Loader2 className="spin" size={13} /> : <span className="status-dot" />}
                    {stateLabels[status.state]}
                  </span>
                  <h1 title={status.serverUrl}>{status.serverUrl}</h1>
                </div>
                <div className="connection-meta">
                  {serverInfo && (
                    <span><Server size={14} /> {serverInfo.title ?? serverInfo.name} <code>{serverInfo.version}</code></span>
                  )}
                  {status.connectionInfo?.protocolVersion && (
                    <span>Protocol <code>{status.connectionInfo.protocolVersion}</code></span>
                  )}
                  <span title={status.connectionId}>ID <code>{shortId(status.connectionId)}</code></span>
                  <span className={`stream-indicator ${streamOnline ? "online" : ""}`}>
                    <span className="status-dot" /> {streamOnline ? "Live" : "Reconnecting"}
                  </span>
                </div>
                <button className="secondary-button danger" onClick={disconnect}>
                  <Power size={15} /> Disconnect
                </button>
              </section>

              {status.errorMessage && (
                <div className="callout danger"><CircleAlert size={18} /> <span>{status.errorMessage}</span></div>
              )}

              {authorizationUrl && status.state === "awaiting_authorization" && (
                <div className="authorization-banner">
                  <KeyRound size={20} />
                  <div>
                    <strong>Authorization is required</strong>
                    <p>Continue in the provider window. The inspector never stores the returned code or token.</p>
                  </div>
                  <a className="primary-button" href={authorizationUrl} target="_blank" rel="noreferrer">
                    Authorize <ExternalLink size={15} />
                  </a>
                </div>
              )}

              <nav className="view-tabs" role="tablist">
                <button role="tab" aria-selected={view === "requests"} className={view === "requests" ? "active" : ""} onClick={() => navigate({ page: "connection", connectionId, view: "requests" }, { replace: true })}>
                  <ArrowLeftRight size={16} /> Requests <span>{requestCount}</span>
                </button>
                <button role="tab" aria-selected={view === "tools"} className={view === "tools" ? "active" : ""} onClick={() => navigate({ page: "connection", connectionId, view: "tools" }, { replace: true })}>
                  <Wrench size={16} /> Tools <span>{tools.length}</span>
                </button>
              </nav>

              {view === "requests" ? (
                <RequestLog events={events} onClear={() => setEvents([])} />
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
            </div>
          ) : connectionId ? (
            <div className="panel-empty tall"><Loader2 className="spin" size={22} /><span>Loading connection…</span></div>
          ) : (
            <div className="empty-state">
              <div className="empty-icon"><CircleOff size={28} /></div>
              <h1>No active connection</h1>
              <p>Connect to an MCP server to see every HTTP request the client makes, step through authorization, and call its tools.</p>
              <button className="primary-button" onClick={() => navigate({ page: "new" })}><Plus size={16} /> New connection</button>
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
  const [cimdProfiles, setCimdProfiles] = useState<CimdProfileInfo[]>([]);
  const [cimdProfilesError, setCimdProfilesError] = useState<string | null>(null);
  const update = <K extends keyof ConnectionForm>(key: K, value: ConnectionForm[K]) =>
    setForm((current) => ({ ...current, [key]: value }));

  useEffect(() => {
    let active = true;
    api.listCimdProfiles()
      .then((profiles) => {
        if (!active) return;
        setCimdProfiles(profiles);
        setCimdProfilesError(null);
      })
      .catch((error) => {
        if (!active) return;
        setCimdProfilesError(error instanceof Error ? error.message : "Could not load CIMD profiles");
      });
    return () => { active = false; };
  }, []);

  const selectAuthType = (authType: AuthType) => {
    setForm((current) => ({
      ...current,
      authType,
      tokenAuthMethod: "client_secret_basic",
      cimdProfile: authType === "cimd_client_credentials" ? "jwks" :
        authType === "cimd_authorization_code" ? "none" : current.cimdProfile,
    }));
  };

  const isCimd = form.authType === "cimd_authorization_code" ||
    form.authType === "cimd_client_credentials";
  const selectedCimdProfile = cimdProfiles.find((profile) => profile.id === form.cimdProfile);

  return (
    <div className="setup-wrap">
      <div className="setup-intro">
        <h1>Connect to an MCP server</h1>
        <p>Configure the Ballerina MCP client, then watch every HTTP request it makes and call the server's tools.</p>
      </div>

      <form className="setup-card" onSubmit={onSubmit}>
        <div className="form-section-heading">
          <h3>Server</h3>
          <p>The MCP endpoint the Ballerina client connects to.</p>
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
          <h3>Authorization</h3>
          <p>How the client gets an access token. Secrets are cleared from the browser once you connect.</p>
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
              <span className="radio-mark" />
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
                    <strong>Choose a backend-managed CIMD client</strong>
                    <small>The inspector owns the signing key. Only its public key is exposed through the selected document.</small>
                  </span>
                </div>
                <label className="field">
                  <span>Client ID Metadata profile</span>
                  <select
                    required
                    value={form.cimdProfile}
                    onChange={(event) => update("cimdProfile", event.target.value as CimdProfile)}
                  >
                    {cimdProfiles.map((profile) => (
                      <option
                        key={profile.id}
                        value={profile.id}
                        disabled={form.authType === "cimd_client_credentials" && !profile.supportsClientCredentials}
                      >
                        {profile.label}
                        {form.authType === "cimd_client_credentials" && !profile.supportsClientCredentials
                          ? " (authorization code only)"
                          : ""}
                      </option>
                    ))}
                  </select>
                </label>
                {cimdProfilesError && <div className="form-notice error"><CircleAlert size={15} />{cimdProfilesError}</div>}
                {selectedCimdProfile && !selectedCimdProfile.url.startsWith("https://") && (
                  <div className="form-notice warning">
                    <CircleAlert size={15} />
                    Local preview only. Deploy the backend on HTTPS and configure its public origin before using this client ID with an authorization server.
                  </div>
                )}
                {selectedCimdProfile && (
                  <div className="signing-fields">
                    <div className="signing-heading">
                      <LockKeyhole size={16} />
                      <span><strong>{selectedCimdProfile.label}</strong><small>{selectedCimdProfile.description}</small></span>
                    </div>
                    <label className="field">
                      <span>Client ID Metadata Document</span>
                      <div className="input-with-icon locked">
                        <LockKeyhole size={15} />
                        <input readOnly value={selectedCimdProfile.url} />
                        <a href={selectedCimdProfile.url} target="_blank" rel="noreferrer" title="Open metadata document"><ExternalLink size={14} /></a>
                      </div>
                    </label>
                    <div className="field-grid">
                      <label className="field"><span>Token endpoint authentication</span><input readOnly value={selectedCimdProfile.tokenEndpointAuthMethod} /></label>
                      {form.authType === "cimd_authorization_code" && (
                        <label className="field"><span>Registered redirect URI</span><input readOnly value={selectedCimdProfile.redirectUri} /></label>
                      )}
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="field-grid">
                <label className="field"><span>Issuer</span><input type="url" required value={form.issuer} onChange={(e) => update("issuer", e.target.value)} placeholder="https://auth.example.com" /></label>
                <label className="field"><span>Client ID</span><input required value={form.clientId} onChange={(e) => update("clientId", e.target.value)} placeholder="mcp-inspector" autoComplete="off" /></label>
              </div>
            )}

            {form.authType === "authorization_code" && (
              <label className="field"><span>Redirect URI</span><input type="url" required value={form.redirectUri} onChange={(e) => update("redirectUri", e.target.value)} /></label>
            )}

            {!isCimd && (
              <>
                <label className="field">
                  <span>Token endpoint authentication</span>
                  <select
                    value={form.tokenAuthMethod}
                    onChange={(event) => update("tokenAuthMethod", event.target.value as SecretMethod)}
                  >
                    <option value="client_secret_basic">Client secret — HTTP Basic</option>
                    <option value="client_secret_post">Client secret — request body</option>
                  </select>
                </label>
                <label className="field"><span>Client secret</span><input type="password" required value={form.clientSecret} onChange={(e) => update("clientSecret", e.target.value)} placeholder="Not persisted" autoComplete="new-password" /></label>
              </>
            )}

            <label className="field"><span>Scopes <em>optional, separated by spaces or commas</em></span><input value={form.scopes} onChange={(e) => update("scopes", e.target.value)} placeholder="openid profile tools.read" /></label>
          </div>
        )}

        <div className="form-actions">
          {onCancel && <button className="secondary-button" type="button" onClick={onCancel}>Cancel</button>}
          <button className="primary-button" disabled={submitting || (isCimd && !selectedCimdProfile)}>
            {submitting && <Loader2 className="spin" size={16} />}
            {submitting ? "Connecting" : "Connect"}
          </button>
        </div>
      </form>
    </div>
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
  const editorRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!selected) return;
    editorRef.current?.focus();
  }, [selected?.name]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!connected || !selected) return;
    const invokeOnShortcut = (event: globalThis.KeyboardEvent) => {
      if (event.key !== "Enter" || !(event.metaKey || event.ctrlKey)) return;
      event.preventDefault();
      if (!calling) onCall();
    };
    window.addEventListener("keydown", invokeOnShortcut);
    return () => window.removeEventListener("keydown", invokeOnShortcut);
  }, [calling, connected, onCall, selected]);

  if (!connected) {
    return (
      <div className="panel-empty tall">
        <Wrench size={26} />
        <strong>Waiting for a connection</strong>
        <span>Tools become available after the MCP handshake completes.</span>
      </div>
    );
  }
  return (
    <section className="tools-layout">
      <div className="tool-list-panel">
        <div className="panel-title">
          <h3>Tools {tools.length > 0 && <span className="count">{tools.length}</span>}</h3>
          <button className="icon-button" onClick={onRefresh} disabled={loading} title="Reload tools/list" aria-label="Reload tools">
            <RefreshCw className={loading ? "spin" : ""} size={16} />
          </button>
        </div>
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
              <span>The initialize response for {protocolVersion ?? "this connection"} did not declare a tools capability, so tools/list was not sent.</span>
            </div>
          )}
          {!error && !loading && toolsAdvertised && tools.length === 0 && (
            <div className="panel-empty"><CircleOff size={22} /><strong>No tools returned</strong><span>The server advertised tools, but tools/list returned an empty list.</span></div>
          )}
          {!error && !loading && !capabilityKnown && (
            <div className="panel-empty"><Loader2 className="spin" size={22} /><span>Reading negotiated server capabilities…</span></div>
          )}
          {tools.map((tool) => (
            <button key={tool.name} className={selected?.name === tool.name ? "active" : ""} onClick={() => onSelect(tool)}>
              <span className="tool-copy">
                <strong>{tool.title ?? tool.name}</strong>
                <small>{tool.description ?? "No description provided"}</small>
              </span>
            </button>
          ))}
        </div>
      </div>
      <div className="tool-workbench">
        {!selected ? (
          <div className="panel-empty tall">
            <Braces size={26} />
            <strong>Select a tool</strong>
            <span>Review its input schema, provide JSON arguments, and invoke it.</span>
          </div>
        ) : (
          <>
            <div className="tool-heading">
              <div>
                <h2>{selected.title ?? selected.name}</h2>
                {selected.description && <p>{selected.description}</p>}
              </div>
              {selected.title && <code className="tool-name">{selected.name}</code>}
            </div>
            <details className="detail-block">
              <summary><span>Input schema</span></summary>
              <CodeBlock value={JSON.stringify(selected.inputSchema ?? {})} maxHeight={320} />
            </details>
            <label className="editor-label" htmlFor="tool-arguments"><span>Arguments</span><small>JSON object</small></label>
            <textarea
              id="tool-arguments"
              className="json-editor"
              spellCheck={false}
              value={argumentsText}
              ref={editorRef}
              onChange={(e) => onArguments(e.target.value)}
            />
            <div className="invoke-row">
              <span className="hint"><kbd>{MOD_KEY}</kbd> <kbd>Enter</kbd> to invoke</span>
              <button className="primary-button" onClick={onCall} disabled={calling}>
                {calling ? <Loader2 className="spin" size={16} /> : <Send size={15} />}
                {calling ? "Invoking" : "Invoke tool"}
              </button>
            </div>
            {result !== null && (
              <div className="result-block">
                <div className="detail-block-title">
                  <span>Result</span>
                  {(result as { isError?: unknown } | null)?.isError === true
                    ? <small className="error-label"><CircleAlert size={14} /> Tool returned an error</small>
                    : <small className="success-label"><Check size={14} /> Completed</small>}
                </div>
                <CodeBlock value={JSON.stringify(result)} maxHeight={480} />
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}
