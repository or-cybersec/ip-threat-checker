import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useState, type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";

const STORAGE_KEY = "ip-threat-checker.settings";

export type Settings = {
  explanations: boolean;
  examples: boolean;
  introOpen: boolean;
  detailsOpen: boolean;
  feedStatus: boolean;
  rememberAddress: boolean;
  lastAddress: string;
  theme: "dark" | "light";
};

const DEFAULTS: Settings = {
  explanations: true,
  examples: true,
  introOpen: true,
  detailsOpen: false,
  feedStatus: true,
  rememberAddress: false,
  lastAddress: "",
  theme: "dark",
};

type SettingsValue = {
  settings: Settings;
  ready: boolean;
  update: (patch: Partial<Settings>) => void;
};

const SettingsContext = createContext<SettingsValue | null>(null);

function readSettings(): Settings {
  if (typeof localStorage === "undefined") return DEFAULTS;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULTS;
    const parsed = JSON.parse(raw) as Partial<Settings>;
    return {
      explanations: parsed.explanations !== false,
      examples: parsed.examples !== false,
      introOpen: parsed.introOpen !== false,
      detailsOpen: parsed.detailsOpen === true,
      feedStatus: parsed.feedStatus !== false,
      rememberAddress: parsed.rememberAddress === true,
      lastAddress: typeof parsed.lastAddress === "string" ? parsed.lastAddress.slice(0, 200) : "",
      theme: parsed.theme === "light" ? "light" : "dark",
    };
  } catch {
    return DEFAULTS;
  }
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(DEFAULTS);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    setSettings(readSettings());
    setReady(true);
  }, []);

  useLayoutEffect(() => {
    if (!ready) return;
    document.documentElement.dataset.theme = settings.theme;
  }, [ready, settings.theme]);

  const update = useCallback((patch: Partial<Settings>) => {
    setSettings((current) => {
      const next = { ...current, ...patch };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  return <SettingsContext.Provider value={{ settings, ready, update }}>{children}</SettingsContext.Provider>;
}

export function useSettings(): SettingsValue {
  return useContext(SettingsContext) ?? { settings: DEFAULTS, ready: true, update: () => {} };
}

function Choice({
  checked,
  onChange,
  title,
  text,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  title: string;
  text: string;
}) {
  return (
    <label className="flex items-start gap-3 rounded-md border border-line bg-bg px-3 py-3">
      <input type="checkbox" className="mt-1 size-4" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span>
        <span className="block text-sm font-medium">{title}</span>
        <span className="block text-xs text-pretty text-faint">{text}</span>
      </span>
    </label>
  );
}

export function SettingsDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { settings, update } = useSettings();

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-bg/80" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 max-h-[min(40rem,calc(100vh-2rem))] w-[min(100%-1.5rem,32rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-line bg-surface p-4 shadow-none">
          <div className="flex items-start justify-between gap-3">
            <div>
              <Dialog.Title className="text-base font-semibold">Settings</Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-pretty text-muted">
                Saved in this browser. Nothing here is sent with a lookup.
              </Dialog.Description>
            </div>
            <Dialog.Close className="grid size-11 place-items-center rounded-md text-muted hover:bg-raised hover:text-fg" aria-label="Close">
              <X className="size-4" />
            </Dialog.Close>
          </div>
          <div className="mt-4 grid gap-3">
            <Choice
              checked={settings.theme === "light"}
              onChange={(light) => update({ theme: light ? "light" : "dark" })}
              title="Light background"
              text="A light page. Off returns to the dark one. Saved in this browser."
            />
            <Choice
              checked={settings.explanations}
              onChange={(explanations) => update({ explanations })}
              title="Explain labels"
              text="Hovering a dotted label shows a short explanation. Off leaves the page plain."
            />
            <Choice
              checked={settings.examples}
              onChange={(examples) => update({ examples })}
              title="Show example addresses"
              text="Google DNS, Cloudflare, Quad9, and the Nmap test address under the input."
            />
            <Choice
              checked={settings.introOpen}
              onChange={(introOpen) => update({ introOpen })}
              title="Open “New here?” at the start"
              text="The short introduction is open when the page loads. Turn this off once you know the page."
            />
            <Choice
              checked={settings.detailsOpen}
              onChange={(detailsOpen) => update({ detailsOpen })}
              title="Open the detail sections"
              text="Reputation, threats, Shodan, DNS, OTX, and the raw record start open instead of closed."
            />
            <Choice
              checked={settings.feedStatus}
              onChange={(feedStatus) => update({ feedStatus })}
              title="Show source status"
              text="The row that says whether each source answered, is cached, or needs a key."
            />
            <Choice
              checked={settings.rememberAddress}
              onChange={(rememberAddress) => update(rememberAddress ? { rememberAddress } : { rememberAddress, lastAddress: "" })}
              title="Remember the last address"
              text="The input is filled again after a refresh. Turn this off on a shared computer."
            />
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
