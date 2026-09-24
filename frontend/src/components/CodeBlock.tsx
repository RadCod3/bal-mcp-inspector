import { Check, Copy } from "lucide-react";
import { ReactNode, useEffect, useState } from "react";

const JSON_TOKEN = /("(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

function highlightJson(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  let cursor = 0;
  for (const match of text.matchAll(JSON_TOKEN)) {
    const token = match[0];
    const start = match.index ?? 0;
    if (start > cursor) nodes.push(text.slice(cursor, start));
    let className = "tok-number";
    if (token.startsWith("\"")) className = token.trimEnd().endsWith(":") ? "tok-key" : "tok-string";
    else if (token === "true" || token === "false") className = "tok-boolean";
    else if (token === "null") className = "tok-null";
    nodes.push(<span key={start} className={className}>{token}</span>);
    cursor = start + token.length;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return nodes;
}

// Pretty-prints JSON when the text parses; anything else is shown as-is.
export function prettyBody(text: string): { text: string; json: boolean } {
  try {
    return { text: JSON.stringify(JSON.parse(text), null, 2), json: true };
  } catch {
    return { text, json: false };
  }
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1400);
    return () => window.clearTimeout(timer);
  }, [copied]);

  return (
    <button
      type="button"
      className="copy-button"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => setCopied(true));
      }}
      title={label}
      aria-label={label}
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
      <span>{copied ? "Copied" : "Copy"}</span>
    </button>
  );
}

export function CodeBlock({ value, maxHeight }: { value: string; maxHeight?: number }) {
  const body = prettyBody(value);
  return (
    <div className="code-block">
      <CopyButton value={body.text} />
      <pre style={maxHeight ? { maxHeight } : undefined}>
        <code>{body.json ? highlightJson(body.text) : body.text}</code>
      </pre>
    </div>
  );
}
