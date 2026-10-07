import { createFileRoute } from "@tanstack/react-router";

import { Dashboard } from "@/components/intel/dashboard";

export const Route = createFileRoute("/")({ component: Dashboard });
