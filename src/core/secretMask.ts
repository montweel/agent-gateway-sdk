/**
 * Credentials are write-only through the admin API: responses carry a mask, never the value.
 *
 *   maskSecret("123456789:AAH...xyz9") -> "••••••••xyz9"   (last 4 kept so admins can tell which one is set)
 *   isMasked(v)                         a value that starts with the mask is "unchanged": saving it back
 *                                       keeps the stored secret instead of overwriting it with bullets
 *
 * Admins who need the real value (e.g. to copy a gateway-generated signing secret into the receiving
 * system) ask for it explicitly with GET /secrets/:field, admin only, never cached.
 */

export const SECRET_MASK = "••••••••";

export function maskSecret(value: string): string {
  if (!value) return "";
  return value.length <= 8 ? SECRET_MASK : `${SECRET_MASK}${value.slice(-4)}`;
}

export function isMasked(value: unknown): boolean {
  return typeof value === "string" && value.startsWith(SECRET_MASK);
}

/** A URL reduced to its origin, for viewers: "https://hooks.zapier.com/••••••••". */
export function maskUrl(value: string): string {
  if (!value) return "";
  try {
    return `${new URL(value).origin}/${SECRET_MASK}`;
  } catch {
    return SECRET_MASK;
  }
}
