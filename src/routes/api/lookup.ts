import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/lookup")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { handleLookup } = await import("@/lib/intel/run.server");
        return handleLookup(request);
      },
    },
  },
});
