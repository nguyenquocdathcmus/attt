const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const TOKEN_KEY = "attt_token";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(TOKEN_KEY);
}

/** Build a ws:// URL for a scan's WebSocket stream. */
export function scanWsUrl(scanId: string): string {
  const base = API_URL.replace(/^http/, "ws");
  const token = getToken() ?? "";
  return `${base}/api/v1/scans/${scanId}/ws?token=${encodeURIComponent(token)}`;
}

export async function apiFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  const body = options.body;
  if (
    body &&
    !(body instanceof FormData) &&
    !(body instanceof URLSearchParams) &&
    !headers.has("Content-Type")
  ) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}${text ? `: ${text}` : ""}`);
  }
  return res.json() as Promise<T>;
}

export const apiGet  = <T>(path: string) => apiFetch<T>(path, { method: "GET" });
export const apiPost = <T, B>(path: string, body: B) =>
  apiFetch<T>(path, { method: "POST", body: JSON.stringify(body) });
export const apiPostForm = <T>(path: string, body: URLSearchParams) =>
  apiFetch<T>(path, {
    method: "POST",
    body,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
