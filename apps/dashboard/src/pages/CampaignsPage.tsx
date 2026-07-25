import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, fetchCampaigns } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import type { CampaignSummary } from "../types";

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<CampaignSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchCampaigns()
      .then((data) => {
        if (!cancelled) setCampaigns(data.campaigns);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "Failed to load campaigns.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return <div className="panel panel-error">{error}</div>;
  }

  if (campaigns === null) {
    return <div className="panel">Loading campaigns...</div>;
  }

  if (campaigns.length === 0) {
    return (
      <div className="panel">
        No campaigns found yet. Run <code>cyberjection run --config ... --target ...</code> to
        create one.
      </div>
    );
  }

  return (
    <div className="panel">
      <h1>Campaigns</h1>
      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Status</th>
            <th>Total cost</th>
            <th>Started</th>
          </tr>
        </thead>
        <tbody>
          {campaigns.map((campaign) => (
            <tr key={campaign.id}>
              <td>
                <Link to={`/campaigns/${campaign.id}`}>{campaign.name}</Link>
              </td>
              <td>
                <StatusBadge status={campaign.status} />
              </td>
              <td>${campaign.total_cost.toFixed(2)}</td>
              <td>{campaign.started_at ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
