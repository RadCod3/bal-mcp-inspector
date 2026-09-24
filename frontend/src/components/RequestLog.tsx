import { ArrowDown, ArrowDownLeft, ArrowUpRight, CircleAlert, Info, Search, Trash2, X } from "lucide-react";
import { KeyboardEvent, ReactNode, useEffect, useMemo, useRef, useState } from "react";
import type { InspectorEvent } from "../types";
import {
  buildExchanges,
  durationMs,
  exchangeMatches,
  exchangeStatus,
  formatDuration,
  formatTime,
  headerValue,
  hostOf,
  HttpExchange,
  requestName,
  responseProblem,
  targetLabel,
} from "../requests";
import { CodeBlock, CopyButton } from "./CodeBlock";

export function RequestLog({ events, onClear }: { events: InspectorEvent[]; onClear: () => void }) {
  const exchanges = useMemo(() => buildExchanges(events), [events]);
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [atBottom, setAtBottom] = useState(true);
  const [seenCount, setSeenCount] = useState(0);
  const rowsRef = useRef<HTMLDivElement>(null);

  const query = search.trim().toLowerCase();
  const visible = useMemo(
    () => exchanges.filter((exchange) => exchangeMatches(exchange, query)),
    [exchanges, query],
  );
  const selected = exchanges.find((exchange) => exchange.id === selectedId) ?? null;
  // Latency bars share one scale so rows can be compared at a glance.
  const slowest = useMemo(
    () => Math.max(1, ...visible.map((exchange) => durationMs(exchange) ?? 0)),
    [visible],
  );

  const scrollToLatest = (behavior: ScrollBehavior = "smooth") => {
    const rows = rowsRef.current;
    if (rows) rows.scrollTo({ top: rows.scrollHeight, behavior });
  };

  // Stick to the newest request while the list is scrolled to the bottom; otherwise count what arrived.
  useEffect(() => {
    if (!atBottom) return;
    setSeenCount(visible.length);
    const frame = window.requestAnimationFrame(() => scrollToLatest("auto"));
    return () => window.cancelAnimationFrame(frame);
  }, [atBottom, visible.length]);

  const trackScroll = () => {
    const rows = rowsRef.current;
    if (!rows) return;
    setAtBottom(rows.scrollHeight - rows.scrollTop - rows.clientHeight < 24);
  };

  const unseen = atBottom ? 0 : Math.max(0, visible.length - seenCount);

  const moveSelection = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      setSelectedId(null);
      return;
    }
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    event.preventDefault();
    const index = visible.findIndex((exchange) => exchange.id === selectedId);
    const nextIndex = event.key === "ArrowDown"
      ? Math.min(visible.length - 1, index + 1)
      : Math.max(0, index === -1 ? visible.length - 1 : index - 1);
    const next = visible[nextIndex];
    if (!next) return;
    setSelectedId(next.id);
    rowsRef.current?.querySelector(`[data-id="${next.id}"]`)?.scrollIntoView({ block: "nearest" });
  };

  return (
    <section className="requests-panel">
      <div className="panel-toolbar">
        <label className="search-box">
          <Search size={16} />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Filter by method, URL, status or body"
          />
          {search && (
            <button type="button" onClick={() => setSearch("")} aria-label="Clear filter"><X size={14} /></button>
          )}
        </label>
        <span className="toolbar-count">
          {query ? `${visible.length} of ${exchanges.length}` : exchanges.length} {exchanges.length === 1 ? "request" : "requests"}
        </span>
        <button
          type="button"
          className="ghost-button toolbar-clear"
          onClick={() => {
            setSelectedId(null);
            onClear();
          }}
          disabled={events.length === 0}
          title="Remove the captured requests from this view"
        >
          <Trash2 size={15} /> Clear
        </button>
      </div>

      <div className={`requests-body ${selected ? "with-detail" : ""}`}>
        <div className="request-table">
          <div className="request-head" aria-hidden>
            <span>Method</span>
            <span>Status</span>
            <span>Request</span>
            <span className="col-target">Target</span>
            <span className="col-time">Started</span>
            <span className="col-duration">Duration</span>
          </div>
          <div
            className="request-rows"
            ref={rowsRef}
            onScroll={trackScroll}
            onKeyDown={moveSelection}
            tabIndex={0}
            role="listbox"
            aria-label="HTTP requests"
          >
            {visible.length === 0 ? (
              <div className="panel-empty">
                <strong>{exchanges.length === 0 ? "No requests yet" : "No requests match this filter"}</strong>
                <span>
                  {exchanges.length === 0
                    ? "Requests the MCP client sends, and the responses it gets back, show up here as they happen."
                    : "Try a different method, path or status code."}
                </span>
              </div>
            ) : visible.map((exchange) => (
              <RequestRow
                key={exchange.id}
                exchange={exchange}
                slowest={slowest}
                selected={exchange.id === selectedId}
                onSelect={() => setSelectedId(exchange.id === selectedId ? null : exchange.id)}
              />
            ))}
          </div>
          {unseen > 0 && (
            <button type="button" className="new-requests" onClick={() => scrollToLatest()}>
              <ArrowDown size={15} /> {unseen} new {unseen === 1 ? "request" : "requests"}
            </button>
          )}
        </div>
        {selected && <RequestDetail key={selected.id} exchange={selected} onClose={() => setSelectedId(null)} />}
      </div>
    </section>
  );
}

function MethodBadge({ method }: { method?: string }) {
  const value = method ?? "HTTP";
  return <span className={`method-badge method-${value.toLowerCase()}`}>{value}</span>;
}

function StatusBadge({ exchange }: { exchange: HttpExchange }) {
  const status = exchangeStatus(exchange);
  return (
    <span className={`status-badge ${status.tone}`}>
      <span className="status-dot" />
      {status.label}
    </span>
  );
}

function RequestRow({ exchange, slowest, selected, onSelect }: {
  exchange: HttpExchange;
  slowest: number;
  selected: boolean;
  onSelect: () => void;
}) {
  const name = requestName(exchange);
  const elapsed = durationMs(exchange);
  const pending = !exchange.response && exchange.errors.length === 0;
  // Square-root scale keeps fast requests visible next to a slow outlier.
  const barWidth = elapsed === undefined ? 0 : Math.max(3, Math.sqrt(elapsed / slowest) * 100);
  const problem = responseProblem(exchange);
  const host = hostOf(exchange.request.eventUrl);

  return (
    <div
      className={`request-row ${selected ? "selected" : ""}`}
      data-id={exchange.id}
      role="option"
      aria-selected={selected}
      onClick={onSelect}
    >
      <span><MethodBadge method={exchange.request.httpMethod} /></span>
      <span><StatusBadge exchange={exchange} /></span>
      <span className="request-name" title={exchange.request.eventUrl}>
        <strong className={name.isRpc ? "rpc" : ""}>{name.label}</strong>
        {name.detail && <span className="name-detail">{name.detail}</span>}
        {problem && <span className="flag danger">{problem}</span>}
        <span className="name-host">{host}</span>
      </span>
      <span className="col-target muted">{targetLabel(exchange.request.eventTarget)}</span>
      <span className="col-time muted">{formatTime(exchange.request.timestamp)}</span>
      <span className="col-duration">
        <span className="latency-value">{pending ? "waiting" : formatDuration(elapsed) || "—"}</span>
        <span className={`latency-track ${pending ? "pending" : ""}`} aria-hidden>
          <span style={{ width: `${barWidth}%` }} />
        </span>
      </span>
    </div>
  );
}

function RequestDetail({ exchange, onClose }: { exchange: HttpExchange; onClose: () => void }) {
  const name = requestName(exchange);
  const duration = formatDuration(durationMs(exchange));
  const url = exchange.request.eventUrl ?? "";

  return (
    <aside className="request-detail" aria-label="Request details">
      <header className="detail-header">
        <div className="detail-title">
          <MethodBadge method={exchange.request.httpMethod} />
          <StatusBadge exchange={exchange} />
          <h3>{name.label}</h3>
          {name.detail && <span className="name-detail">{name.detail}</span>}
        </div>
        <button type="button" className="icon-button" onClick={onClose} aria-label="Close details" title="Close (Esc)">
          <X size={16} />
        </button>
      </header>

      <div className="detail-scroll">
        <div className="detail-url">
          <code>{url}</code>
          <CopyButton value={url} label="Copy URL" />
        </div>

        <dl className="detail-facts">
          <div><dt>Target</dt><dd>{targetLabel(exchange.request.eventTarget)}</dd></div>
          <div><dt>Started</dt><dd className="mono">{formatTime(exchange.request.timestamp)}</dd></div>
          <div><dt>Duration</dt><dd className="mono">{duration || "—"}</dd></div>
          <div><dt>Sequence</dt><dd className="mono">#{exchange.request.sequence}</dd></div>
        </dl>

        {exchange.errors.map((event) => (
          <div className="callout danger" key={event.sequence}>
            <CircleAlert size={16} />
            <span>{event.eventMessage ?? "The client reported an error for this request."}</span>
          </div>
        ))}
        {exchange.notes.map((event) => (
          <div className="callout info" key={event.sequence}>
            <Info size={16} />
            <span>{event.eventMessage ?? "The server responded with an OAuth authorization challenge."}</span>
          </div>
        ))}

        <DetailSection title="Request" direction="out" aside={`${exchange.request.httpMethod ?? "HTTP"} to ${hostOf(url)}`}>
          <Headers event={exchange.request} />
          <Body event={exchange.request} label="Body" />
        </DetailSection>

        <DetailSection
          title="Response"
          direction="in"
          aside={exchange.response?.statusCode !== undefined ? `HTTP ${exchange.response.statusCode}` : "Waiting"}
        >
          {exchange.response ? (
            <>
              <Headers event={exchange.response} />
              {exchange.bodies.length === 0 ? (
                <Block title="Body"><p className="empty-note">No body captured.</p></Block>
              ) : exchange.bodies.map((event, index) => (
                <Body
                  key={event.sequence}
                  event={event}
                  label={exchange.bodies.length > 1 ? `Message ${index + 1}` : "Body"}
                  hint={event.eventMessage}
                />
              ))}
            </>
          ) : (
            <p className="empty-note">No response received yet.</p>
          )}
        </DetailSection>
      </div>
    </aside>
  );
}

function DetailSection({ title, direction, aside, children }: {
  title: string;
  direction: "out" | "in";
  aside?: string;
  children: ReactNode;
}) {
  return (
    <section className={`detail-section ${direction}`}>
      <div className="detail-section-title">
        <h4>{direction === "out" ? <ArrowUpRight size={16} /> : <ArrowDownLeft size={16} />}{title}</h4>
        {aside && <span>{aside}</span>}
      </div>
      {children}
    </section>
  );
}

function Block({ title, hint, children, collapsible, defaultOpen = true }: {
  title: string;
  hint?: string;
  children: ReactNode;
  collapsible?: boolean;
  defaultOpen?: boolean;
}) {
  if (collapsible) {
    return (
      <details className="detail-block" open={defaultOpen}>
        <summary><span>{title}</span>{hint && <small>{hint}</small>}</summary>
        {children}
      </details>
    );
  }
  return (
    <div className="detail-block">
      <div className="detail-block-title"><span>{title}</span>{hint && <small>{hint}</small>}</div>
      {children}
    </div>
  );
}

function Headers({ event }: { event: InspectorEvent }) {
  const entries = Object.entries(event.eventHeaders ?? {})
    .sort(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) return null;
  return (
    <Block title="Headers" hint={String(entries.length)} collapsible defaultOpen={!event.eventBody}>
      <KeyValueTable rows={entries.map(([key, value]) => [key, Array.isArray(value) ? value.join(", ") : value])} />
    </Block>
  );
}

function Body({ event, label, hint }: { event: InspectorEvent; label: string; hint?: string }) {
  if (!event.eventBody) {
    return event.eventType === "http.request" ? null : <Block title={label}><p className="empty-note">Empty body.</p></Block>;
  }
  const contentType = headerValue(event, "content-type") ?? "";
  if (contentType.includes("application/x-www-form-urlencoded")) {
    const params = [...new URLSearchParams(event.eventBody).entries()];
    return <Block title={label} hint="form"><KeyValueTable rows={params} /></Block>;
  }
  return <Block title={label} hint={hint}><CodeBlock value={event.eventBody} maxHeight={520} /></Block>;
}

function KeyValueTable({ rows }: { rows: [string, string][] }) {
  return (
    <table className="kv-table">
      <tbody>
        {rows.map(([key, value], index) => (
          <tr key={`${key}-${index}`}>
            <th>{key}</th>
            <td>{value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
