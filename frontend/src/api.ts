export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const res = await fetch("/api" + path, {
    method,
    headers: { "Content-Type": "application/json", "X-PacketBreaker": "local" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const value = await res.json();
  if (!res.ok)
    throw new Error(
      typeof value.detail === "string"
        ? value.detail
        : JSON.stringify(value.detail),
    );
  return value;
}
export const time = (v: number | null | undefined) =>
  v == null
    ? "unknown"
    : new Date(Math.round(v * 1000)).toISOString().slice(11, 23) + " UTC";
export const num = (v: number | null | undefined, unit = "", digits = 2) =>
  v == null
    ? "unknown"
    : v.toLocaleString(undefined, { maximumFractionDigits: digits }) + unit;

export function reverseTuple(value: string): string {
  try {
    const [proto, src, sport, dst, dport] = JSON.parse(value);
    return JSON.stringify([proto, dst, dport, src, sport]);
  } catch {
    return "";
  }
}
