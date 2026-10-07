import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/keys")({
  server: {
    handlers: {
      GET: async () => {
        const { envFlags } = await import("@/lib/intel/run.server");
        return Response.json(envFlags());
      },
    },
  },
});
