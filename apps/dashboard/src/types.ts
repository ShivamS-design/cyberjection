// TypeScript mirrors of the JSON shapes cyberjection.api.app's handlers
// return (see that module's docstring for the endpoint list). Kept as
// plain interfaces rather than a schema-validation library (zod, etc.) --
// the backend and frontend are versioned and deployed together (see
// apps/dashboard/Dockerfile and the repo-root docker-compose.yml), so a
// shape mismatch is a build-time/integration concern this project catches
// via cyberjection.api's own test suite (tests/unit/test_api.py,
// tests/unit/test_api_persistence.py), not something the dashboard needs
// to defend against at runtime.

export interface CampaignSummary {
  id: string;
  name: string;
  status: string;
  total_cost: number;
  started_at: string | null;
  finished_at: string | null;
}

export interface TestSummary {
  id: string;
  campaign_id: string;
  target_id: string;
  strategy: string;
  status: string;
  score: number;
  verdict: string;
  created_at: string | null;
}

export interface TurnDetail {
  turn_number: number;
  prompt: string;
  response: string;
  latency_ms: number;
}

export interface FindingDetail {
  severity: string;
  owasp_category: string;
  description: string;
}

export interface MetricDetail {
  prompt_tokens: number;
  completion_tokens: number;
  total_cost: number;
  judge_tier_used: number;
}

export interface TestDetail extends TestSummary {
  seed_prompt: string;
  turns: TurnDetail[];
  findings: FindingDetail[];
  metrics: MetricDetail | null;
}

export interface CampaignDetail extends CampaignSummary {
  tests: TestSummary[];
}

export interface DiscoveredPlugin {
  group: string;
  alias: string;
  qualified_name: string;
}

export interface PluginsResponse {
  registered: Record<string, string[]>;
  discovered: DiscoveredPlugin[];
  failures: string[];
}

export interface ApiErrorBody {
  error: string;
  detail?: string;
}
