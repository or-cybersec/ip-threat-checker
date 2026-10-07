import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useEffect, useState } from "react";

import type { FeedKeys } from "@/lib/intel/types";

const STORAGE_KEY = "ip-threat-checker.feed-keys";
const OPT_IN_KEY = "ip-threat-checker.use-workspace-keys";

export type EnvFlags = {
  virustotal: boolean;
  abuseipdb: boolean;
  greynoise: boolean;
  shodan: boolean;
  ipinfo: boolean;
  otx: boolean;
  mdti: boolean;
};

type Field = {
  key: keyof FeedKeys;
  label: string;
  hint: string;
  href?: string;
  env?: keyof EnvFlags;
};

const FIELDS: Field[] = [
  {
    key: "virustotal",
    label: "VirusTotal",
    hint: "Reputation, engines, passive DNS",
    href: "https://www.virustotal.com/gui/my-apikey",
    env: "virustotal",
  },
  {
    key: "abuseipdb",
    label: "AbuseIPDB",
    hint: "Confidence score and report categories",
    href: "https://www.abuseipdb.com/api",
    env: "abuseipdb",
  },
  {
    key: "greynoise",
    label: "GreyNoise",
    hint: "Optional. Community lookup is best-effort, IPv4-only, and has no RIOT. A key adds RIOT and the full IP record.",
    href: "https://docs.greynoise.io/docs/using-the-greynoise-community-api",
    env: "greynoise",
  },
  {
    key: "shodan",
    label: "Shodan",
    hint: "Optional. InternetDB ports are free. A key adds service banners, OS, and a honeypot score.",
    href: "https://account.shodan.io/",
    env: "shodan",
  },
  {
    key: "ipinfo",
    label: "ipinfo",
    hint: "Optional token for VPN, proxy, Tor, and hosting flags.",
    href: "https://ipinfo.io/signup",
    env: "ipinfo",
  },
  {
    key: "otx",
    label: "AlienVault OTX",
    hint: "Pulses, malware families, campaigns",
    href: "https://otx.alienvault.com/api",
    env: "otx",
  },
  {
    key: "mdtiTenant",
    label: "Defender TI tenant",
    hint: "Directory (tenant) ID",
    href: "https://learn.microsoft.com/en-us/graph/api/resources/security-threatintelligence-overview",
    env: "mdti",
  },
  { key: "mdtiClientId", label: "Defender TI client ID", hint: "App registration client ID", env: "mdti" },
  {
    key: "mdtiClientSecret",
    label: "Defender TI client secret",
    hint: "Client secret. Needs ThreatIntelligence.Read.All and an MDTI license.",
    env: "mdti",
  },
];

export function readKeys(): FeedKeys {
  if (typeof localStorage === "undefined") return {};
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object") return {};
    return parsed as FeedKeys;
  } catch {
    return {};
  }
}

export function readWorkspaceOptIn(): boolean {
  if (typeof localStorage === "undefined") return false;
  return localStorage.getItem(OPT_IN_KEY) === "1";
}

function writeWorkspaceOptIn(on: boolean) {
  localStorage.setItem(OPT_IN_KEY, on ? "1" : "0");
}

function writeKeys(keys: FeedKeys) {
  const cleaned: FeedKeys = {};
  for (const field of FIELDS) {
    const value = keys[field.key]?.trim();
    if (value) cleaned[field.key] = value;
  }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(cleaned));
}

export function KeysDialog({
  open,
  onOpenChange,
  envFlags,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  envFlags: EnvFlags | null;
}) {
  const [draft, setDraft] = useState<FeedKeys>({});
  const [useWorkspace, setUseWorkspace] = useState(false);
  const workspaceAvailable = Boolean(envFlags && Object.values(envFlags).some(Boolean));

  useEffect(() => {
    if (open) {
      setDraft(readKeys());
      setUseWorkspace(readWorkspaceOptIn());
    }
  }, [open]);

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-bg/80" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 max-h-[min(40rem,calc(100vh-2rem))] w-[min(100%-1.5rem,36rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-line bg-surface p-4 shadow-none">
          <div className="flex items-start justify-between gap-3">
            <div>
              <Dialog.Title className="text-base font-semibold">Feed credentials</Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-pretty text-muted">
                Saved in this browser. Sent with a lookup, never written to the log.
              </Dialog.Description>
            </div>
            <Dialog.Close className="grid size-11 place-items-center rounded-md text-muted hover:bg-raised hover:text-fg" aria-label="Close">
              <X className="size-4" />
            </Dialog.Close>
          </div>
          <form
            className="mt-4 grid gap-3"
            onSubmit={(event) => {
              event.preventDefault();
              writeKeys(draft);
              writeWorkspaceOptIn(useWorkspace);
              onOpenChange(false);
            }}
          >
            {workspaceAvailable ? (
              <label className="flex items-start gap-3 rounded-md border border-line bg-bg px-3 py-3">
                <input
                  type="checkbox"
                  className="mt-1 size-4"
                  checked={useWorkspace}
                  onChange={(event) => setUseWorkspace(event.target.checked)}
                />
                <span>
                  <span className="block text-sm font-medium">Use workspace keys</span>
                  <span className="block text-xs text-pretty text-faint">
                    Blank fields then use a key configured on the server. Off unless you turn it on.
                  </span>
                </span>
              </label>
            ) : null}
            {FIELDS.map((field) => {
              const workspace = Boolean(field.env && envFlags?.[field.env] && useWorkspace);
              return (
                <label key={field.key} className="grid gap-1">
                  <span className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
                    <span className="font-medium">{field.label}</span>
                    {workspace && !draft[field.key] ? (
                      <span className="font-mono text-xs text-ok">Workspace key will be used</span>
                    ) : null}
                  </span>
                  <input
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    value={draft[field.key] ?? ""}
                    onChange={(event) => setDraft((current) => ({ ...current, [field.key]: event.target.value }))}
                    className="h-11 rounded-md border border-line bg-bg px-3 font-mono text-sm text-fg outline-none focus-visible:border-accent"
                  />
                  <span className="text-xs text-faint">
                    {field.hint}
                    {field.href ? (
                      <>
                        {" "}
                        <a href={field.href} target="_blank" rel="noreferrer" className="text-accent underline-offset-2 hover:underline">
                          Get a key
                        </a>
                      </>
                    ) : null}
                  </span>
                </label>
              );
            })}
            <div className="mt-1 flex flex-wrap gap-2">
              <button type="submit" className="h-11 rounded-md bg-accent px-4 text-sm font-medium text-accent-fg">
                Save in this browser
              </button>
              <button
                type="button"
                className="h-11 rounded-md border border-line px-4 text-sm text-muted"
                onClick={() => {
                  localStorage.removeItem(STORAGE_KEY);
                  setDraft({});
                }}
              >
                Clear saved keys
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
