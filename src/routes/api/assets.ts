import { createFileRoute } from "@tanstack/react-router";

import { historyId } from "@/lib/intel/run.server";
import { asRecord } from "@/lib/intel/read";

export const Route = createFileRoute("/api/assets")({
  server: {
    handlers: {
      GET: async () => {
        try {
          const { listAssets } = await import("@/lib/intel/assets.server");
          return Response.json({ rows: await listAssets() });
        } catch (error) {
          console.error("[checker] assets failed", error instanceof Error ? error.message : error);
          return Response.json({ message: "The network list is unavailable." }, { status: 503 });
        }
      },
      POST: async ({ request }) => {
        let body: unknown;
        try {
          const text = await request.text();
          if (text.length > 4_000) return Response.json({ message: "Request is too large." }, { status: 413 });
          body = JSON.parse(text) as unknown;
        } catch {
          return Response.json({ message: "Request body must be JSON." }, { status: 400 });
        }
        const rec = asRecord(body);
        const { parseAsset, addAsset, listAssets } = await import("@/lib/intel/assets.server");
        const parsed = parseAsset(typeof rec?.value === "string" ? rec.value : "", typeof rec?.note === "string" ? rec.note : "");
        if ("error" in parsed) return Response.json({ message: parsed.error }, { status: 400 });
        try {
          const existing = await listAssets();
          if (existing.length >= 40) return Response.json({ message: "The network list is full (40)." }, { status: 400 });
          const asset = await addAsset(parsed.kind, parsed.value, parsed.note);
          return Response.json(asset);
        } catch (error) {
          const message = error instanceof Error ? error.message : "";
          if (/unique|duplicate/i.test(message)) {
            return Response.json({ message: "That entry is already on the list." }, { status: 409 });
          }
          console.error("[checker] asset insert failed", message);
          return Response.json({ message: "The network list is unavailable." }, { status: 503 });
        }
      },
      DELETE: async ({ request }) => {
        const id = historyId(new URL(request.url).searchParams.get("id"));
        if (!id) return Response.json({ message: "Missing entry." }, { status: 400 });
        try {
          const { deleteAsset } = await import("@/lib/intel/assets.server");
          const removed = await deleteAsset(id);
          if (!removed) return Response.json({ message: "That entry is not on the list." }, { status: 404 });
          return Response.json({ deleted: id });
        } catch (error) {
          console.error("[checker] asset delete failed", error instanceof Error ? error.message : error);
          return Response.json({ message: "The network list is unavailable." }, { status: 503 });
        }
      },
    },
  },
});
