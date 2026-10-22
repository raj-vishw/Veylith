// Thin client for the Veylith API. Requests go to our own origin (proxied to FastAPI), so the
// HttpOnly session cookie travels automatically; only the CSRF token is handled here.

export class ApiError extends Error {
  status: number;
  detail: string;
  errors?: { loc: string[]; msg: string }[];
  constructor(status: number, detail: string, errors?: { loc: string[]; msg: string }[]) {
    super(detail);
    this.status = status;
    this.detail = detail;
    this.errors = errors;
  }
}

let csrfToken = "";
export function setCsrfToken(token: string) {
  csrfToken = token;
}

const BASE = "/api/v1";

export async function api<T = any>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  const method = (init.method || "GET").toUpperCase();
  if (method !== "GET" && csrfToken) headers.set("X-CSRF-Token", csrfToken);
  const res = await fetch(BASE + path, { ...init, method, headers, body, credentials: "same-origin", cache: "no-store" });
  if (res.status === 204) return undefined as T;
  const isJson = res.headers.get("content-type")?.includes("application/json");
  const data = isJson ? await res.json() : null;
  if (!res.ok) {
    if (res.status === 401 && typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
      window.location.assign("/login");
    }
    throw new ApiError(res.status, formatDetail(data) || res.statusText, data?.errors);
  }
  return data as T;
}

function formatDetail(data: any): string {
  if (!data) return "";
  if (typeof data.detail === "string") {
    return data.errors?.length ? `${data.detail}: ${data.errors.map((e: any) => `${e.loc.slice(1).join(".")} ${e.msg}`).join("; ")}` : data.detail;
  }
  return "";
}

export const get = <T = any>(path: string) => api<T>(path);
export const post = <T = any>(path: string, json?: unknown) => api<T>(path, { method: "POST", json: json ?? {} });
export const patch = <T = any>(path: string, json: unknown) => api<T>(path, { method: "PATCH", json });
export const del = <T = any>(path: string, json?: unknown) => api<T>(path, { method: "DELETE", json });

export function upload<T = any>(path: string, file: File, fields: Record<string, string> = {}) {
  const form = new FormData();
  form.append("file", file);
  for (const [k, v] of Object.entries(fields)) if (v) form.append(k, v);
  return api<T>(path, { method: "POST", body: form });
}

export async function download(path: string, fallbackName: string) {
  const res = await fetch(BASE + path, { credentials: "same-origin", cache: "no-store" });
  if (!res.ok) {
    const data = await res.json().catch(() => null);
    throw new ApiError(res.status, data?.detail || res.statusText);
  }
  const blob = await res.blob();
  const name = /filename="([^"]+)"/.exec(res.headers.get("content-disposition") || "")?.[1] || fallbackName;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export function qs(params: Record<string, string | number | boolean | undefined | null>) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}
