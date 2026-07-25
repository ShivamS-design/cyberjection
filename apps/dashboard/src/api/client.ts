import type { ApiErrorBody, CampaignDetail, CampaignSummary, PluginsResponse, TestDetail } from "../types";

// Every request is a relative `/api/...` path -- see vite.config.ts's dev
// proxy and apps/dashboard/nginx.conf's production proxy for why this
// code never needs to know the backend's actual host/port.
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

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
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
