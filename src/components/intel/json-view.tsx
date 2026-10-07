import { useEffect, useRef, useState, type ReactNode } from "react";

const PREVIEW_LINES = 16;

export function JsonView({ value }: { value: unknown }) {
  const text = JSON.stringify(value, null, 2) ?? "null";
  const lines = text.split("\n");
  const hidden = Math.max(0, lines.length - PREVIEW_LINES);
  const [full, setFull] = useState(false);
  const preRef = useRef<HTMLPreElement>(null);
  const shown = full || hidden === 0 ? text : lines.slice(0, PREVIEW_LINES).join("\n");

  useEffect(() => {
    if (!full) return;
    const box = preRef.current;
    if (!box) return;
    const fit = () => {
      document.getElementById("raw")?.scrollIntoView({ block: "start" });
      requestAnimationFrame(() => {
        const top = box.getBoundingClientRect().top;
        const available = window.innerHeight - top - 24;
        box.style.maxHeight = `${Math.max(160, available)}px`;
      });
    };
    const frame = requestAnimationFrame(fit);
    window.addEventListener("resize", fit);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", fit);
    };
  }, [full]);

  return (
    <div>
      {hidden > 0 ? (
        <button type="button" className="mb-3 h-11 rounded-md border border-line px-3 text-sm" onClick={() => setFull((open) => !open)}>
          {full ? "Show less" : `Show the rest, ${hidden} lines`}
        </button>
      ) : null}
      <pre
        ref={preRef}
        className={`overflow-x-auto font-mono text-xs leading-relaxed text-fg ${full ? "overflow-y-auto overscroll-contain" : ""}`}
      >
        <code>{tokenize(shown)}</code>
      </pre>
    </div>
  );
}

function tokenize(text: string): ReactNode[] {
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
  const nodes: ReactNode[] = [];
  let last = 0;
  let key = 0;
  for (const match of text.matchAll(re)) {
    const index = match.index ?? 0;
    if (index > last) nodes.push(text.slice(last, index));
    const full = match[0];
    const quoted = match[1];
    const colon = match[2];
    const literal = match[3];
    if (quoted && colon) {
      nodes.push(
        <span key={key} className="text-muted">
          {quoted}
        </span>,
      );
      key += 1;
      nodes.push(colon);
    } else if (quoted) {
      nodes.push(
        <span key={key} className="text-ok">
          {quoted}
        </span>,
      );
      key += 1;
    } else if (literal) {
      nodes.push(
        <span key={key} className={literal === "null" ? "text-faint" : "text-warn"}>
          {literal}
        </span>,
      );
      key += 1;
    } else {
      nodes.push(
        <span key={key} className="text-accent">
          {full}
        </span>,
      );
      key += 1;
    }
    last = index + full.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}
