import { getSql } from "@/lib/db";

import { classifyAddress } from "./address";
import { normalizeAsn, type Asset, type AssetKind } from "./assets";

export async function listAssets(): Promise<Asset[]> {
  const sql = await getSql();
  const rows = await sql.query<{ id: number; kind: string; value: string; note: string }>(
    `select id, kind, value, note from assets order by id desc limit 40`,
  );
  return rows.map((row) => ({
    id: Number(row.id),
    kind: row.kind as AssetKind,
    value: row.value,
    note: row.note,
  }));
}

export async function addAsset(kind: AssetKind, value: string, note: string): Promise<Asset> {
  const sql = await getSql();
  const rows = await sql.query<{ id: number }>(
    `insert into assets (kind, value, note) values ($1, $2, $3) returning id`,
    [kind, value, note],
  );
  const id = rows[0]?.id;
  return { id: Number(id), kind, value, note };
}

export async function deleteAsset(id: number): Promise<boolean> {
  const sql = await getSql();
  const rows = await sql.query<{ id: number }>(`delete from assets where id = $1 returning id`, [id]);
  return rows.length > 0;
}

export function parseAsset(value: string, note: string): { kind: AssetKind; value: string; note: string } | { error: string } {
  const label = note.trim();
  if (!label || label.length > 80) return { error: "Add a short note, up to 80 characters." };
  const raw = value.trim();
  const asn = normalizeAsn(raw);
  if (asn && !raw.includes(".")) return { kind: "asn", value: asn, note: label };
  if (raw.includes("/")) {
    const [base, bits] = raw.split("/");
    const checked = classifyAddress(base ?? "");
    if (!checked.ok) return { error: checked.message };
    if (checked.version !== 4) return { error: "Use an IPv4 range, such as 8.8.8.0/24." };
    const prefix = Number(bits);
    if (!Number.isInteger(prefix) || prefix < 8 || prefix > 32) {
      return { error: "Use a prefix from /8 to /32, such as 8.8.8.0/24." };
    }
    return { kind: "cidr", value: `${checked.ip}/${prefix}`, note: label };
  }
  const checked = classifyAddress(raw);
  if (!checked.ok) return { error: checked.message };
  return { kind: "ip", value: checked.ip, note: label };
}
