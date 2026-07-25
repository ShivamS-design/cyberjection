import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, fetchCampaign } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import type { CampaignDetail } from "../types";

export default function CampaignDetailPage() {
  const { campaignId } = useParams<{ campaignId: string }>();
  const [campaign, setCampaign] = useState<CampaignDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!campaignId) return;
    let cancelled = false;
    setCampaign(null);
    setError(null);
    fetchCampaign(campaignId)
      .then((data) => {
        if (!cancelled) setCampaign(data);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(
          err instanceof ApiError && err.status === 404
            ? "No campaign found with this id."
            : "Failed to load campaign."
        );
      });
    return () => {
      cancelled = true;
    };
  }, [campaignId]);

  if (error) {
    return <div className="panel panel-error">{error}</div>;
  }

  if (campaign === null) {
    return <div className="panel">Loading campaign...</div>;
  }

  return (
    <div className="panel">
      <p>
        <Link to="/">&larr; All campaigns</Link>
      </p>
      <h1>
        {campaign.name} <StatusBadge status={campaign.status} />
      </h1>
      <dl className="meta-list">
        <dt>Total cost</dt>
        <dd>${campaign.total_cost.toFixed(2)}</dd>
        <dt>Started</dt>
        <dd>{campaign.started_at ?? "-"}</dd>
        <dt>Finished</dt>
        <dd>{campaign.finished_at ?? "-"}</dd>
      </dl>

      <h2>Tests</h2>
      {campaign.tests.length === 0 ? (
        <p>No test cases have recorded results for this campaign yet.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Strategy</th>
              <th>Verdict</th>
              <th>Score</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {campaign.tests.map((test) => (
              <tr key={test.id}>
                <td>{test.target_id}</td>
                <td>{test.strategy}</td>
                <td>
                  <Link to={`/campaigns/${campaign.id}/tests/${test.id}`}>
                    <StatusBadge status={test.verdict} />
                  </Link>
                </td>
                <td>{test.score.toFixed(1)}</td>
                <td>{test.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
