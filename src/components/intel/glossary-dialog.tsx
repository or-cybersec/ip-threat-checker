import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useMemo, useState } from "react";

import { GLOSSARY } from "@/components/intel/glossary";

export function GlossaryDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [query, setQuery] = useState("");
  const needle = query.trim().toLowerCase();
  const groups = useMemo(
    () =>
      GLOSSARY.map((group) => ({
        ...group,
        entries: group.entries.filter(
          (entry) => !needle || entry.term.toLowerCase().includes(needle) || entry.text.toLowerCase().includes(needle),
        ),
      })).filter((group) => group.entries.length > 0),
    [needle],
  );

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-bg/80" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 flex max-h-[min(40rem,calc(100vh-2rem))] w-[min(100%-1.5rem,40rem)] -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-lg border border-line bg-surface p-4 shadow-none">
          <div className="flex items-start justify-between gap-3">
            <div>
              <Dialog.Title className="text-base font-semibold">Glossary</Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-pretty text-muted">
                Words on this page, for a first look. Precise, and written so a new analyst can use them.
              </Dialog.Description>
            </div>
            <Dialog.Close className="grid size-11 shrink-0 place-items-center rounded-md text-muted hover:bg-raised hover:text-fg" aria-label="Close">
              <X className="size-4" />
            </Dialog.Close>
          </div>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search, for example ASN or blocklist"
            spellCheck={false}
            className="mt-4 h-11 rounded-md border border-line bg-bg px-3 text-sm outline-none placeholder:text-faint focus-visible:border-accent"
          />
          <div className="mt-4 grid gap-5 overflow-y-auto pr-1">
            {groups.length ? (
              groups.map((group) => (
                <section key={group.title}>
                  <h2 className="text-xs font-medium tracking-wide text-faint uppercase">{group.title}</h2>
                  <dl className="mt-2 grid gap-3">
                    {group.entries.map((entry) => (
                      <div key={entry.term}>
                        <dt className="text-sm font-medium text-fg">{entry.term}</dt>
                        <dd className="text-sm text-pretty text-muted">{entry.text}</dd>
                      </div>
                    ))}
                  </dl>
                </section>
              ))
            ) : (
              <p className="text-sm text-muted">No entry matches that word.</p>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
