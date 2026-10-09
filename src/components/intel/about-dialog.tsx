import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";

export function AboutDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-bg/80" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 max-h-[min(40rem,calc(100vh-2rem))] w-[min(100%-1.5rem,36rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-line bg-surface p-4 shadow-none">
          <div className="flex items-start justify-between gap-3">
            <div>
              <Dialog.Title className="text-base font-semibold">About this page</Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-pretty text-muted">
                What it does, who it is for, and where it stops.
              </Dialog.Description>
            </div>
            <Dialog.Close className="grid size-11 shrink-0 place-items-center rounded-md text-muted hover:bg-raised hover:text-fg" aria-label="Close">
              <X className="size-4" />
            </Dialog.Close>
          </div>
          <div className="mt-4 grid gap-4 text-sm text-pretty text-muted">
            <section>
              <h2 className="text-sm font-medium text-fg">How it works</h2>
              <p className="mt-1">
                Paste a public IP, or a line from a log. A trailing port, as in 8.8.8.8:53, is dropped. The page asks several services at once what they already know: where the network is registered, who reported it, whether the traffic is internet noise rather than a targeted attack, which ports were seen before, and whether it is listed on a blocklist. It does not scan that computer. You can start with no key. The first line says who answered, who stayed quiet, and what that does not prove. The number beside it is this page's score, made by rules, not a score from those services and not a model's verdict. The note under that line is the one to copy into a ticket.
              </p>
            </section>
            <section>
              <h2 className="text-sm font-medium text-fg">Who it is for</h2>
              <p className="mt-1">
                Someone making a first look. A junior analyst, a student, or anyone who has an address from an alert and needs to decide whether to look further before blocking it or closing the ticket.
              </p>
            </section>
            <section>
              <h2 className="text-sm font-medium text-fg">When to use it</h2>
              <ul className="mt-1 grid list-disc gap-1 pl-5">
                <li>One public address from an alert, before you open the same sources in six tabs.</li>
                <li>A shared address, such as public DNS or a cloud host, where blocking on reputation alone would be a mistake.</li>
                <li>A short note you can paste into a ticket.</li>
                <li>Learning what Unknown, a blocklist that does not list the address, and an open port do not prove.</li>
              </ul>
            </section>
            <section>
              <h2 className="text-sm font-medium text-fg">Limits</h2>
              <ul className="mt-1 grid list-disc gap-1 pl-5">
                <li>Unknown is not clean. A source with no key, or no answer, is not a promise.</li>
                <li>A city is where the network is registered, not where a person is.</li>
                <li>Not listed on a blocklist does not mean the address is safe.</li>
                <li>Shodan shows an older record. It does not show which ports are open right now.</li>
                <li>On a VPN, a shared connection, or a hosting address, a report may belong to someone else.</li>
                <li>VirusTotal, AbuseIPDB, OTX, and Defender stay empty until you add a key.</li>
                <li>Critical means escalate. It does not name an attacker.</li>
                <li>The log lasts only while this app is running.</li>
              </ul>
            </section>
            <p>Glossary explains the words on this page. Study more, next to it, lists places to learn the ideas behind a lookup.</p>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
