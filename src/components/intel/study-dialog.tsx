import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";

const START = [
  ["Cloudflare Learning", "https://www.cloudflare.com/learning/", "An address, DNS, and anycast, in short articles."],
  ["Practical Networking", "https://www.practicalnetworking.net/index/networking-fundamentals-how-data-moves-through-the-internet/", "How data moves across the internet. The first module is free."],
  ["TryHackMe Pre-Security", "https://tryhackme.com/path/outline/presecurity", "Practice DNS and WHOIS. Those rooms are free."],
  ["RIPE NCC Academy", "https://academy.ripe.net/", "Who hands addresses out. That is what ASN and RDAP are."],
] as const;

const LONGER = [
  ["Cisco Networking Basics", "https://www.netacad.com/courses/networking-basics?courseLang=en-US", "A free course on how to build a network. About 22 hours."],
  ["Microsoft Learn: networking", "https://learn.microsoft.com/en-us/training/modules/network-fundamentals/", "A short module. It turns toward Azure."],
  ["Professor Messer Network+", "https://www.professormesser.com/network-plus/n10-009/n10-009-video/n10-009-training-course/", "Free videos for the Network+ exam. The notes are paid."],
] as const;

export function StudyDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-bg/80" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 max-h-[min(40rem,calc(100vh-2rem))] w-[min(100%-1.5rem,36rem)] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-line bg-surface p-4 shadow-none">
          <div className="flex items-start justify-between gap-3">
            <div>
              <Dialog.Title className="text-base font-semibold">Study more</Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-pretty text-muted">
                Other sites. They explain the ideas behind a lookup. They do not recommend this page.
              </Dialog.Description>
            </div>
            <Dialog.Close className="grid size-11 shrink-0 place-items-center rounded-md text-muted hover:bg-raised hover:text-fg" aria-label="Close">
              <X className="size-4" />
            </Dialog.Close>
          </div>
          <div className="mt-4 grid gap-5 text-sm">
            <section>
              <h2 className="text-sm font-medium text-fg">Start here</h2>
              <ul className="mt-2 grid gap-3">
                {START.map(([label, href, text]) => (
                  <li key={href}>
                    <a className="text-fg underline" href={href} target="_blank" rel="noopener noreferrer">{label}</a>
                    <p className="text-pretty text-muted">{text}</p>
                  </li>
                ))}
              </ul>
            </section>
            <section>
              <h2 className="text-sm font-medium text-fg">Longer courses</h2>
              <p className="mt-1 text-pretty text-muted">Useful, but they teach a certificate or how to build a network, not how to read one result.</p>
              <ul className="mt-2 grid gap-3">
                {LONGER.map(([label, href, text]) => (
                  <li key={href}>
                    <a className="text-fg underline" href={href} target="_blank" rel="noopener noreferrer">{label}</a>
                    <p className="text-pretty text-muted">{text}</p>
                  </li>
                ))}
              </ul>
            </section>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
