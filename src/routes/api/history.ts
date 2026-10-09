import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/history")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { historyId, listHistory, readHistory } = await import("@/lib/intel/run.server");
        const url = new URL(request.url);
        const id = historyId(url.searchParams.get("id"));
        try {
          if (id) {
            const dossier = await readHistory(id);
            if (!dossier) return Response.json({ message: "That lookup is not in the log." }, { status: 404 });
            return Response.json(dossier);
          }
          const rows = await listHistory();
          return Response.json({ rows });
        } catch (error) {
          console.error("[checker] history failed", error instanceof Error ? error.message : error);
          return Response.json({ message: "The lookup log is unavailable." }, { status: 503 });
        }
      },
      PATCH: async ({ request }) => {
        const { historyId, setHistoryMark } = await import("@/lib/intel/run.server");
        const url = new URL(request.url);
        const id = historyId(url.searchParams.get("id"));
        if (!id) return Response.json({ message: "That lookup is not in the log." }, { status: 400 });
        const body = (await request.json().catch(() => null)) as { marked?: unknown } | null;
        if (!body || typeof body.marked !== "boolean") {
          return Response.json({ message: "Say whether the row stays marked." }, { status: 400 });
        }
        try {
          const ip = await setHistoryMark(id, body.marked);
          if (!ip) return Response.json({ message: "That lookup is not in the log." }, { status: 404 });
          return Response.json({ ip, marked: body.marked });
        } catch (error) {
          console.error("[checker] history mark failed", error instanceof Error ? error.message : error);
          return Response.json({ message: "The lookup log is unavailable." }, { status: 503 });
        }
      },
      DELETE: async ({ request }) => {
        const { clearHistory, clearVerdictHistory, deleteHistory, historyId, isVerdict } = await import("@/lib/intel/run.server");
        const url = new URL(request.url);
        const id = historyId(url.searchParams.get("id"));
        const verdict = url.searchParams.get("verdict");
        try {
          if (id) {
            const removed = await deleteHistory(id);
            if (!removed) return Response.json({ message: "That lookup is not in the log." }, { status: 404 });
            return Response.json({ deleted: id });
          }
          if (verdict) {
            if (!isVerdict(verdict)) return Response.json({ message: "That verdict cannot be cleared in bulk." }, { status: 400 });
            const removed = await clearVerdictHistory(verdict);
            return Response.json({ cleared: verdict, removed });
          }
          await clearHistory();
          return Response.json({ cleared: true });
        } catch (error) {
          console.error("[checker] history clear failed", error instanceof Error ? error.message : error);
          return Response.json({ message: "The lookup log is unavailable." }, { status: 503 });
        }
      },
    },
  },
});
