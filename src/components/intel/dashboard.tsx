import { formatDistanceToNow } from "date-fns";
import { ChevronDown, KeyRound, Radar, Search } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import { InfoTip } from "@/components/intel/info-tip";
import { type EnvFlags, KeysDialog, readKeys, readWorkspaceOptIn } from "@/components/intel/keys-dialog";
import {
  DnsPanel,
  IocPanel,
  Overview,
  Phase,
  RawPanel,
  ReputationPanel,
  ShodanPanel,
  sourceById,
  sourceWord,
  SummaryPanel,
  ThreatPanel,
} from "@/components/intel/sections";
import { FEEDS, type Dossier, type HistoryRow, type IntelPatch, type SourceMeta, type StreamEvent, type Verdict } from "@/lib/intel/types";
import { assetLine, matchAssets, type Asset } from "@/lib/intel/assets";
import { mergePatch } from "@/lib/intel/merge";

const SAMPLES = [
  { ip: "8.8.8.8", label: "Google DNS" },
  { ip: "1.1.1.1", label: "Cloudflare" },
  { ip: "9.9.9.9", label: "Quad9" },
  { ip: "45.33.32.156", label: "scanme.nmap.org" },
];

const NAV = [
  ["overview", "Overview"],
  ["summary", "Summary"],
  ["reputation", "Reputation"],
  ["threats", "Threats"],
  ["shodan", "Shodan"],
  ["dns", "DNS"],
  ["ioc", "OTX"],
  ["raw", "JSON"],
] as const;

const dot: Record<Verdict, string> = {
  critical: "bg-critical",
  suspicious: "bg-warn",
  benign: "bg-ok",
  unknown: "bg-faint",
};

export function Dashboard() {
  const [ip, setIp] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [fatal, setFatal] = useState<string | null>(null);
  const [dossier, setDossier] = useState<Dossier | null>(null);
  const [partial, setPartial] = useState<IntelPatch>({});
  const [sources, setSources] = useState<SourceMeta[]>([]);
  const [meta, setMeta] = useState<{ ip: string; version: 4 | 6; cgnat: boolean } | null>(null);
  const [history, setHistory] = useState<HistoryRow[]>([]);
  const [historyNote, setHistoryNote] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<number | null>(null);
  const [keysOpen, setKeysOpen] = useState(false);
  const [envFlags, setEnvFlags] = useState<EnvFlags | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [assetValue, setAssetValue] = useState("");
  const [assetNote, setAssetNote] = useState("");
  const [assetError, setAssetError] = useState<string | null>(null);
  const requestId = useRef(0);

  useEffect(() => {
    void refreshHistory();
    void refreshAssets();
    void fetch("/api/keys")
      .then((response) => (response.ok ? response.json() : null))
      .then((flags: EnvFlags | null) => {
        if (flags) setEnvFlags(flags);
      })
      .catch(() => undefined);
  }, []);

  async function refreshAssets() {
    try {
      const response = await fetch("/api/assets");
      if (!response.ok) return;
      const body = (await response.json()) as { rows?: Asset[] };
      setAssets(body.rows ?? []);
    } catch {
      setAssetError("The network list is unavailable.");
    }
  }

  async function addAsset(event: FormEvent) {
    event.preventDefault();
    setAssetError(null);
    try {
      const response = await fetch("/api/assets", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ value: assetValue, note: assetNote }),
      });
      const body = (await response.json().catch(() => null)) as { message?: string } | null;
      if (!response.ok) {
        setAssetError(body?.message ?? "Could not add that entry.");
        return;
      }
      setAssetValue("");
      setAssetNote("");
      await refreshAssets();
    } catch {
      setAssetError("Could not add that entry.");
    }
  }

  async function deleteAsset(id: number) {
    const response = await fetch(`/api/assets?id=${id}`, { method: "DELETE" });
    if (!response.ok) {
      setAssetError("Could not remove that entry.");
      return;
    }
    setAssets((current) => current.filter((asset) => asset.id !== id));
  }

  async function refreshHistory() {
    try {
      const response = await fetch("/api/history");
      if (!response.ok) {
        setHistoryNote("Lookup log is unavailable.");
        return;
      }
      const body = (await response.json()) as { rows?: HistoryRow[] };
      setHistory(body.rows ?? []);
      setHistoryNote(null);
    } catch {
      setHistoryNote("Lookup log is unavailable.");
    }
  }

  async function deleteHistoryRow(id: number) {
    try {
      const response = await fetch(`/api/history?id=${id}`, { method: "DELETE" });
      if (!response.ok) {
        setHistoryNote("Could not delete that lookup.");
        return;
      }
      setPendingDelete(null);
      setHistory((current) => current.filter((row) => row.id !== id));
    } catch {
      setHistoryNote("Could not delete that lookup.");
    }
  }

  async function clearHistory(verdict?: Verdict) {
    try {
      const response = await fetch(verdict ? `/api/history?verdict=${verdict}` : "/api/history", { method: "DELETE" });
      if (!response.ok) {
        setHistoryNote("Could not clear the log.");
        return;
      }
      setHistory((current) => (verdict ? current.filter((row) => row.verdict !== verdict) : []));
      setConfirmClear(false);
      setPendingDelete(null);
      setHistoryNote(null);
    } catch {
      setHistoryNote("Could not clear the log.");
    }
  }

  function clearResult() {
    requestId.current += 1;
    setPhase("idle");
    setDossier(null);
    setPartial({});
    setSources([]);
    setMeta(null);
    setFatal(null);
    setNotice(null);
  }

  async function run(nextIp: string) {
    const trimmed = nextIp.trim();
    setIp(trimmed);
    const id = requestId.current + 1;
    requestId.current = id;
    const keep = dossier;
    setPhase("running");
    setFatal(null);
    setNotice(null);
    try {
      const response = await fetch("/api/lookup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ip: trimmed, keys: readKeys(), useWorkspaceKeys: readWorkspaceOptIn() }),
      });
      const type = response.headers.get("content-type") ?? "";
      if (!type.includes("ndjson")) {
        const body = (await response.json().catch(() => null)) as { message?: string } | null;
        if (requestId.current !== id) return;
        setPhase(keep ? "done" : "idle");
        setFatal(body?.message ?? "Lookup failed.");
        return;
      }
      if (!response.body) {
        setPhase(keep ? "done" : "error");
        setFatal("The lookup stream did not start.");
        return;
      }
      setDossier(null);
      setPartial({});
      setSources([]);
      setMeta(null);
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let sawComplete = false;
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        buffer += decoder.decode(chunk.value, { stream: true });
        let newline = buffer.indexOf("\n");
        while (newline >= 0) {
          const line = buffer.slice(0, newline).trim();
          buffer = buffer.slice(newline + 1);
          if (line && requestId.current === id) {
            const event = JSON.parse(line) as StreamEvent;
            if (event.type === "meta") {
              setMeta({ ip: event.ip, version: event.version, cgnat: event.cgnat });
              setIp(event.ip);
              if (event.fromLine) setNotice(`Using ${event.ip} from the pasted line.`);
            }
            if (event.type === "fragment") {
              setSources((current) => [...current.filter((source) => source.id !== event.source.id), event.source]);
              setPartial((current) => mergePatch(current, event.patch));
            }
            if (event.type === "fatal") {
              setPhase("error");
              setFatal(event.message);
            }
            if (event.type === "complete") {
              sawComplete = true;
              setDossier(event.dossier);
              setSources(event.dossier.sources);
              setPhase("done");
              setHistory((current) => {
                if (!event.dossier.historyId) return current;
                const row: HistoryRow = {
                  id: event.dossier.historyId,
                  ip: event.dossier.ip,
                  verdict: event.dossier.verdict,
                  score: event.dossier.score,
                  summary: event.dossier.summary,
                  createdAt: event.dossier.queriedAt,
                };
                return [row, ...current.filter((item) => item.id !== row.id)].slice(0, 30);
              });
            }
          }
          newline = buffer.indexOf("\n");
        }
      }
      if (requestId.current === id && !sawComplete) {
        setPhase((current) => (current === "running" ? "error" : current));
        setFatal((current) => current ?? "The lookup ended before a score was ready.");
      }
    } catch {
      if (requestId.current !== id) return;
      setPhase("error");
      setFatal("The lookup was interrupted.");
    }
  }

  async function openCase(id: number) {
    requestId.current += 1;
    setPhase("running");
    setFatal(null);
    try {
      const response = await fetch(`/api/history?id=${id}`);
      if (!response.ok) {
        setPhase("error");
        setFatal("That case is not in the log.");
        return;
      }
      const saved = (await response.json()) as Dossier;
      setDossier(saved);
      setPartial({});
      setSources(saved.sources ?? []);
      setMeta({ ip: saved.ip, version: saved.version, cgnat: saved.cgnat });
      setIp(saved.ip);
      setPhase("done");
    } catch {
      setPhase("error");
      setFatal("Could not open that case.");
    }
  }

  async function copyText(label: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setNotice(`${label} copied.`);
    } catch {
      setNotice("Copy is blocked in this browser.");
    }
  }

  const activeSources = dossier?.sources ?? sources;
  const missingKeys = FEEDS.filter((feed) => sourceById(activeSources, feed.id)?.status === "no_key");
  const viewIp = dossier?.ip ?? meta?.ip ?? "";
  const geo = dossier?.geo ?? partial.geo ?? {};
  const asn = dossier?.asn ?? partial.asn ?? {};
  const matches = matchAssets(viewIp, asn.asn, assets);
  const owned = assetLine(matches, dossier?.verdict);
  const steps =
    owned && (dossier?.verdict === "unknown" || dossier?.verdict === "benign")
      ? ["No further action unless a feed turns hostile."]
      : (dossier?.actions ?? []);
  const raw = useMemo(() => dossier ?? (phase === "running" ? { ip: viewIp, ...partial, sources: activeSources } : null), [dossier, phase, viewIp, partial, activeSources]);

  return (
    <div className="min-h-screen bg-bg text-fg">
      <header className="border-b border-line">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-3 py-3 sm:px-5">
          <div className="flex items-center gap-3">
            <span className="grid size-11 shrink-0 place-items-center rounded-md border border-line bg-surface text-accent">
              <Radar className="size-5" aria-hidden="true" />
            </span>
            <div>
              <h1 className="text-base font-semibold">IP Threat Checker</h1>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setKeysOpen(true)}
            className="inline-flex h-11 items-center gap-2 rounded-md border border-line bg-surface px-3 text-sm"
          >
            <KeyRound className="size-4 text-accent" aria-hidden="true" />
            Credentials
          </button>
        </div>
      </header>

      <div className="mx-auto grid max-w-6xl gap-4 px-3 py-4 sm:px-5 lg:grid-cols-[16rem_minmax(0,1fr)]">
        <main className="min-w-0 lg:col-start-2 lg:row-start-1">
          <details className="group mb-4 rounded-lg border border-line bg-surface">
            <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 px-4 text-sm font-semibold [&::-webkit-details-marker]:hidden">
              <span className="flex-1">New here?</span>
              <ChevronDown className="size-4 text-muted group-open:rotate-180" aria-hidden="true" />
            </summary>
            <ul className="grid list-disc gap-2 border-t border-line px-8 py-3 text-sm text-pretty text-muted">
              <li>Paste a public IP, or a whole line from a log. The app takes the address.</li>
              <li>It does not scan the computer. It asks other services what they already know.</li>
              <li>If a service stays silent, that is not a clean result.</li>
              <li>A city is where the network is registered, not where a person is.</li>
              <li>The note under the result can be copied into a ticket.</li>
            </ul>
          </details>
          <form
            className="grid gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              void run(ip);
            }}
          >
            <label className="grid gap-1">
              <span className="text-sm font-medium">IP address</span>
              <span className="flex flex-col gap-2 sm:flex-row">
                <span className="relative min-w-0 flex-1">
                  <Search className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-faint" aria-hidden="true" />
                  <input
                    value={ip}
                    onChange={(event) => setIp(event.target.value)}
                    placeholder="8.8.8.8 or a log line"
                    spellCheck={false}
                    autoCapitalize="off"
                    autoCorrect="off"
                    inputMode="text"
                    className="h-11 w-full rounded-md border border-line bg-surface pr-3 pl-10 font-mono text-sm text-fg outline-none placeholder:text-faint focus-visible:border-accent"
                  />
                </span>
                <button
                  type="submit"
                  disabled={phase === "running" || !ip.trim()}
                  className="h-11 rounded-md bg-accent px-4 text-sm font-medium text-accent-fg disabled:bg-raised disabled:text-muted"
                >
                  {phase === "running" ? "Querying feeds…" : "Analyze"}
                </button>
              </span>
            </label>
            <div className="flex flex-wrap gap-2">
              {SAMPLES.map((sample) => (
                <button
                  key={sample.ip}
                  type="button"
                  onClick={() => setIp(sample.ip)}
                  disabled={phase === "running"}
                  className="h-11 rounded-md border border-line bg-surface px-3 text-left text-sm disabled:opacity-50"
                >
                  <span className="font-mono">{sample.ip}</span>
                  <span className="text-faint"> · {sample.label}</span>
                </button>
              ))}
            </div>
            <p className="text-sm text-muted">
              VirusTotal, AbuseIPDB, OTX, and Defender need a key. The others run without one.
            </p>
          </form>

          {fatal ? (
            <p className="mt-3 rounded-md bg-critical-dim px-3 py-2 text-sm text-critical" role="alert">
              {fatal}
            </p>
          ) : null}
          {notice ? <p className="mt-3 text-sm text-muted">{notice}</p> : null}

          {phase !== "idle" || dossier ? (
            <>
              <nav className="sticky top-0 z-20 mt-4 -mx-3 flex gap-1 overflow-x-auto border-b border-line bg-bg px-3 py-2 sm:-mx-5 sm:px-5">
                {NAV.map(([id, label]) => (
                  <a key={id} href={`#${id}`} className="inline-flex h-11 shrink-0 items-center rounded-md px-2 text-sm text-muted hover:text-fg">
                    {label}
                  </a>
                ))}
              </nav>
              <div className="mt-4 grid gap-3">
                <Overview
                  ip={viewIp}
                  version={dossier?.version ?? meta?.version}
                  geo={geo}
                  asn={asn}
                  cgnat={dossier?.cgnat ?? meta?.cgnat}
                  assetNote={owned}
                  tags={dossier?.tags ?? []}
                  findings={dossier?.findings ?? []}
                  verdict={dossier?.verdict}
                  score={dossier?.score}
                  phase={phase}
                />
                <SummaryPanel
                  phase={phase}
                  summary={dossier?.summary ?? ""}
                  recommendation={dossier?.recommendation ?? ""}
                  actions={steps}
                  changes={dossier?.changes}
                  previousAt={dossier?.previousAt}
                  verdict={dossier?.verdict}
                  logStatus={dossier?.logStatus}
                  toolbar={
                    dossier ? (
                      <>
                        <button
                          type="button"
                          className="h-11 rounded-md border border-line px-3 text-sm"
                          onClick={() => void copyText("Ticket", dossier.summary)}
                        >
                          Copy for ticket
                        </button>
                        <button type="button" className="h-11 rounded-md border border-line px-3 text-sm text-muted" onClick={() => void copyText("JSON", JSON.stringify(dossier, null, 2))}>
                          Copy JSON
                        </button>
                        <button type="button" className="h-11 rounded-md border border-line px-3 text-sm text-muted" onClick={() => void run(dossier.ip)}>
                          Re-query
                        </button>
                        <button type="button" className="h-11 rounded-md border border-line px-3 text-sm text-muted" onClick={clearResult}>
                          Clear result
                        </button>
                      </>
                    ) : (
                      <button type="button" className="h-11 rounded-md border border-line px-3 text-sm text-muted" onClick={clearResult}>
                        Clear result
                      </button>
                    )
                  }
                />
                <div className="flex flex-wrap items-center gap-2">
                  <InfoTip
                    label="How to read feed status"
                    text="Live means we just asked. Cached means the answer is a few minutes old. Limited means the source said no. No key means we could not ask."
                  />
                  {FEEDS.map((feed) => {
                    const source = sourceById(activeSources, feed.id);
                    const state = feedState(source, phase === "running");
                    return (
                      <span key={feed.id} className="inline-flex h-8 items-center gap-1.5 rounded-md bg-surface px-2 font-mono text-xs text-muted">
                        <span className={`size-1.5 rounded-full ${state.dot}`} aria-hidden="true" />
                        {feed.label}
                        <span className="text-faint">{state.word}</span>
                      </span>
                    );
                  })}
                </div>
                {missingKeys.length ? (
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-line bg-surface px-3 py-2">
                    <p className="text-sm text-muted">No key for {missingKeys.map((feed) => feed.label).join(", ")}.</p>
                    <button type="button" onClick={() => setKeysOpen(true)} className="h-11 shrink-0 rounded-md border border-line px-3 text-sm">
                      Add credentials
                    </button>
                  </div>
                ) : null}
                <div className="flex items-center">
                  <h2 className="text-sm font-semibold">Details</h2>
                  <InfoTip
                    label="What the closed sections mean"
                    text="Not listed on one blocklist is not safe. Threat labels come from other services. Shodan is their old record, not a scan we ran. The city is who owns the network, not a person. A public list is not your case."
                  />
                </div>
                <ReputationPanel
                  phase={phase}
                  source={sourceById(activeSources, "virustotal")}
                  blockSource={sourceById(activeSources, "spamhaus")}
                  reputation={dossier?.reputation ?? partial.reputation ?? null}
                  spamhaus={dossier?.blocklist?.spamhaus ?? partial.blocklist?.spamhaus ?? null}
                />
                <ThreatPanel
                  phase={phase}
                  abuseSource={sourceById(activeSources, "abuseipdb")}
                  noiseSource={sourceById(activeSources, "greynoise")}
                  mdtiSource={sourceById(activeSources, "mdti")}
                  abuse={dossier?.abuse ?? partial.abuse ?? null}
                  greynoise={dossier?.greynoise ?? partial.greynoise ?? null}
                  mdti={dossier?.mdti ?? partial.mdti ?? null}
                />
                <ShodanPanel phase={phase} source={sourceById(activeSources, "shodan")} shodan={dossier?.shodan ?? partial.shodan ?? null} />
                <DnsPanel
                  phase={phase}
                  source={sourceById(activeSources, "whois")}
                  whois={dossier?.whois ?? partial.whois ?? null}
                  passiveDns={dossier?.passiveDns ?? []}
                  timeline={dossier?.timeline ?? []}
                />
                <IocPanel phase={phase} source={sourceById(activeSources, "otx")} otx={dossier?.otx ?? partial.otx ?? null} />
                <RawPanel value={raw} />
              </div>
            </>
          ) : null}
        </main>
        <aside className="min-w-0 lg:sticky lg:top-4 lg:col-start-1 lg:row-start-1 lg:self-start">
          <details className="group mb-4 rounded-lg border border-line bg-surface">
            <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 px-3 text-sm font-semibold [&::-webkit-details-marker]:hidden">
              <span className="flex-1">Our network{assets.length ? ` · ${assets.length}` : ""}</span>
              <ChevronDown className="size-4 text-muted group-open:rotate-180" aria-hidden="true" />
            </summary>
            <div className="border-t border-line px-3 py-3">
              <p className="text-xs text-pretty text-faint">Known resolvers, ranges, and ASNs. A match says do not block, unless the feeds are hostile.</p>
              <form className="mt-2 grid gap-2" onSubmit={(event) => void addAsset(event)}>
              <input
                value={assetValue}
                onChange={(event) => setAssetValue(event.target.value)}
                placeholder="8.8.8.8, 8.8.8.0/24, or AS15169"
                className="h-11 rounded-md border border-line bg-surface px-3 font-mono text-sm"
              />
              <input
                value={assetNote}
                onChange={(event) => setAssetNote(event.target.value)}
                placeholder="Note, for example our DNS"
                className="h-11 rounded-md border border-line bg-surface px-3 text-sm"
              />
              <button type="submit" className="h-11 rounded-md border border-line px-3 text-sm">
                Add
              </button>
            </form>
            {assetError ? <p className="mt-2 text-xs text-warn">{assetError}</p> : null}
            {assets.length ? (
              <ul className="mt-2 grid gap-1">
                {assets.map((asset) => (
                  <li key={asset.id} className="flex min-h-11 items-center gap-2 rounded-md border border-line bg-surface px-3 py-2">
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-xs">{asset.value}</span>
                      <span className="block truncate text-xs text-faint">{asset.note}</span>
                    </span>
                    <button type="button" onClick={() => void deleteAsset(asset.id)} className="h-11 shrink-0 px-2 text-xs text-muted">
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            ) : null}
            </div>
          </details>
          <div className="mb-2">
            <h2 className="text-sm font-semibold">Workspace log</h2>
            <p className="text-xs text-faint">Shared on this workspace</p>
            {history.length > 0 && !confirmClear ? (
              <button type="button" onClick={() => setConfirmClear(true)} className="mt-1 h-11 px-2 text-sm text-muted">
                Clear
              </button>
            ) : null}
          </div>
          {confirmClear ? (
            <div className="mb-2 rounded-md border border-line bg-surface px-3 py-2">
              <p className="text-sm text-pretty text-muted">Pick a verdict to remove those rows. The others stay. Clear all removes the whole log.</p>
              <div className="mt-2 flex flex-wrap gap-2">
                {(["benign", "unknown", "suspicious", "critical"] as const)
                  .filter((verdict) => history.some((row) => row.verdict === verdict))
                  .map((verdict) => (
                    <button
                      key={verdict}
                      type="button"
                      onClick={() => void clearHistory(verdict)}
                      className="h-11 rounded-md border border-line px-3 text-sm"
                    >
                      Clear {verdict}
                    </button>
                  ))}
                <button type="button" onClick={() => void clearHistory()} className="h-11 rounded-md bg-critical-dim px-3 text-sm text-critical">
                  Clear all
                </button>
                <button type="button" onClick={() => setConfirmClear(false)} className="h-11 rounded-md border border-line px-3 text-sm">
                  Cancel
                </button>
              </div>
            </div>
          ) : null}
          <div className="grid max-h-72 gap-1 overflow-y-auto">
            {history.length === 0 ? (
              <p className="text-sm text-muted">{historyNote ?? "Lookups on this workspace are listed here."}</p>
            ) : (
              latestByIp(history).map((row) => (
                <div
                  key={row.id}
                  className={`flex min-h-11 min-w-0 items-stretch rounded-md border ${
                    dossier?.historyId === row.id ? "border-accent bg-raised" : "border-line bg-surface"
                  }`}
                >
                  <button type="button" onClick={() => void openCase(row.id)} className="min-w-0 flex-1 px-3 py-2 text-left">
                    <span className="flex items-center gap-2">
                      <span className={`size-2 shrink-0 rounded-full ${dot[row.verdict]}`} aria-hidden="true" />
                      <span className="truncate font-mono text-sm">{row.ip}</span>
                    </span>
                    <span className="mt-0.5 block text-xs text-faint">
                      {row.verdict} · {row.score} · {safeAgo(row.createdAt)}
                    </span>
                  </button>
                  {pendingDelete === row.id ? (
                    <span className="flex shrink-0">
                      <button
                        type="button"
                        onClick={() => void deleteHistoryRow(row.id)}
                        className="h-11 px-2 text-xs text-critical"
                      >
                        Confirm
                      </button>
                      <button type="button" onClick={() => setPendingDelete(null)} className="h-11 px-2 text-xs text-muted">
                        Cancel
                      </button>
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setPendingDelete(row.id)}
                      aria-label={`Delete ${row.ip} from the log`}
                      className="h-11 shrink-0 px-2 text-xs text-muted"
                    >
                      Delete
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
          {historyNote && history.length ? <p className="mt-2 text-xs text-warn">{historyNote}</p> : null}
        </aside>
      </div>
      <KeysDialog open={keysOpen} onOpenChange={setKeysOpen} envFlags={envFlags} />
    </div>
  );
}

function feedState(source: SourceMeta | undefined, running: boolean): { dot: string; word: string } {
  if (!source) return { dot: running ? "bg-warn" : "bg-line", word: running ? "querying" : "waiting" };
  const word = sourceWord(source);
  if (source.status === "error") return { dot: "bg-critical", word };
  if (source.status === "no_key" || source.status === "rate_limited") return { dot: "bg-warn", word };
  if (source.status === "unsupported") return { dot: "bg-faint", word };
  if (source.status === "ok" || source.status === "empty") return { dot: "bg-ok", word };
  return { dot: "bg-warn", word };
}

function latestByIp(rows: HistoryRow[]): HistoryRow[] {
  const seen = new Set<string>();
  return rows.filter((row) => {
    if (seen.has(row.ip)) return false;
    seen.add(row.ip);
    return true;
  });
}

function safeAgo(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return formatDistanceToNow(date, { addSuffix: true });
}
