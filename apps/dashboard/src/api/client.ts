import type { ApiErrorBody, CampaignDetail, CampaignSummary, PluginsResponse, TestDetail } from "../types";

// Every request is a relative `/api/...` path: in development vite.config.ts
// proxies it, and in production `cyberjection serve --dashboard-dir` serves
// this app and the API from the same origin, so this code never needs to
// know the backend's actual host/port.
const API_BASE = "/api";

export class ApiError extends Error {
  status: number;
  body: ApiErrorBody | null;

  constructor(status: number, body: ApiErrorBody | null) {
    super(body?.detail ?? body?.error ?? `Request failed with status ${status}`);
    this.status = status;
    this.body = body;
  }
}

// When the server runs with CYBERJECTION_API_TOKEN, /api/* requires a bearer
// token. It is asked for once and kept in sessionStorage (this tab only,
// cleared when the tab closes) -- never in localStorage or the URL.
const TOKEN_KEY = "cyberjection.apiToken";

function storedToken(): string | null {
  try {
    return window.sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

async function request(path: string): Promise<Response> {
  const token = storedToken();
  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  return fetch(`${API_BASE}${path}`, { headers });
}

async function getJson<T>(path: string): Promise<T> {
  let response = await request(path);
  if (response.status === 401) {
    const entered = window.prompt("This Cyberjection server requires an API token:");
    if (entered) {
      try {
        window.sessionStorage.setItem(TOKEN_KEY, entered.trim());
      } catch {
        // storage unavailable: the token is used for this request only
      }
      response = await request(path);
    }
  }
  const contentType = response.headers.get("content-type") ?? "";
  const body = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    throw new ApiError(response.status, body as ApiErrorBody | null);
  }
  return body as T;
}

export function fetchCampaigns(limit = 20): Promise<{ campaigns: CampaignSummary[] }> {
  return getJson(`/campaigns?limit=${encodeURIComponent(String(limit))}`);
}

export function fetchCampaign(campaignId: string): Promise<CampaignDetail> {
  return getJson(`/campaigns/${encodeURIComponent(campaignId)}`);
}

export function fetchTest(campaignId: string, testId: string): Promise<TestDetail> {
  return getJson(
    `/campaigns/${encodeURIComponent(campaignId)}/tests/${encodeURIComponent(testId)}`
  );
}

export function fetchPlugins(): Promise<PluginsResponse> {
  return getJson(`/plugins`);
}
