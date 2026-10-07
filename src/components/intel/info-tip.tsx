import * as Popover from "@radix-ui/react-popover";
import { Info } from "lucide-react";
import { useRef, useState } from "react";

export function InfoTip({ label, text }: { label: string; text: string }) {
  const [open, setOpen] = useState(false);
  const pinned = useRef(false);

  return (
    <Popover.Root
      open={open}
      onOpenChange={(next) => {
        if (!next) pinned.current = false;
        setOpen(next);
      }}
    >
      <Popover.Anchor asChild>
        <button
          type="button"
          aria-label={label}
          aria-expanded={open}
          onMouseEnter={() => setOpen(true)}
          onMouseLeave={() => {
            if (!pinned.current) setOpen(false);
          }}
          onClick={(event) => {
            event.stopPropagation();
            pinned.current = !pinned.current;
            setOpen(pinned.current);
          }}
          className="grid size-11 shrink-0 place-items-center rounded-md text-faint hover:bg-raised hover:text-fg"
        >
          <Info className="size-4" aria-hidden="true" />
        </button>
      </Popover.Anchor>
      <Popover.Portal>
        <Popover.Content
          side="bottom"
          align="end"
          sideOffset={6}
          collisionPadding={12}
          onOpenAutoFocus={(event) => event.preventDefault()}
          onCloseAutoFocus={(event) => event.preventDefault()}
          onMouseEnter={() => setOpen(true)}
          onMouseLeave={() => {
            if (!pinned.current) setOpen(false);
          }}
          className="z-50 w-72 rounded-md border border-line bg-bg px-3 py-2 text-sm text-pretty text-fg outline-none"
        >
          {text}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
