import type { FeedKeys } from "./types";

export function resolveKeys(client: FeedKeys, useWorkspace: boolean): FeedKeys {
  const env = process.env;
  const pick = (fromClient: string | undefined, fromEnv: string | undefined) =>
    fromClient || (useWorkspace ? fromEnv?.trim() || undefined : undefined);
  return {
    virustotal: pick(client.virustotal, env.VIRUSTOTAL_API_KEY),
    abuseipdb: pick(client.abuseipdb, env.ABUSEIPDB_API_KEY),
    greynoise: pick(client.greynoise, env.GREYNOISE_API_KEY),
    shodan: pick(client.shodan, env.SHODAN_API_KEY),
    ipinfo: pick(client.ipinfo, env.IPINFO_TOKEN),
    otx: pick(client.otx, env.OTX_API_KEY),
    mdtiTenant: pick(client.mdtiTenant, env.MDTI_TENANT_ID),
    mdtiClientId: pick(client.mdtiClientId, env.MDTI_CLIENT_ID),
    mdtiClientSecret: pick(client.mdtiClientSecret, env.MDTI_CLIENT_SECRET),
  };
}
