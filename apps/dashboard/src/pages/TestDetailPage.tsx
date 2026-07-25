import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, fetchTest } from "../api/client";
import StatusBadge from "../components/StatusBadge";
import type { TestDetail } from "../types";

export default function TestDetailPage() {
  const { campaignId, testId } = useParams<{ campaignId: string; testId: string }>();
  const [test, setTest] = useState<TestDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!campaignId || !testId) return;
    let cancelled = false;
    setTest(null);
    setError(null);
    fetchTest(campaignId, testId)
      .then((data) => {
        if (!cancelled) setTest(data);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(
          err instanceof ApiError && err.status === 404
            ? "No test found with this id."
            : "Failed to load test."
        );
      });
    return () => {
      cancelled = true;
    };
  }, [campaignId, testId]);

  if (error) {
    return <div className="panel panel-error">{error}</div>;
  }

  if (test === null) {
    return <div className="panel">Loading test...</div>;
  }

  return (
    <div className="panel">
      <p>
        <Link to={`/campaigns/${campaignId}`}>&larr; Back to campaign</Link>
      </p>
      <h1>
        {test.strategy} vs {test.target_id} <StatusBadge status={test.verdict} />
      </h1>
      <dl className="meta-list">
        <dt>Score</dt>
        <dd>{test.score.toFixed(1)}</dd>
        <dt>Status</dt>
        <dd>{test.status}</dd>
      </dl>

      <h2>Seed prompt</h2>
      <pre className="code-block">{test.seed_prompt}</pre>

      {test.metrics && (
        <>
          <h2>Metrics</h2>
          <dl className="meta-list">
            <dt>Prompt tokens</dt>
            <dd>{test.metrics.prompt_tokens}</dd>
            <dt>Completion tokens</dt>
            <dd>{test.metrics.completion_tokens}</dd>
            <dt>Total cost</dt>
            <dd>${test.metrics.total_cost.toFixed(4)}</dd>
            <dt>Judge tier used</dt>
            <dd>{test.metrics.judge_tier_used}</dd>
          </dl>
        </>
      )}

      <h2>Conversation transcript</h2>
      {test.turns.length === 0 ? (
        <p>No turns recorded for this test.</p>
      ) : (
        <ol className="transcript">
          {test.turns.map((turn) => (
            <li key={turn.turn_number} className="transcript-turn">
              <div className="transcript-role">Turn {turn.turn_number} -- prompt</div>
              <pre className="code-block">{turn.prompt}</pre>
              <div className="transcript-role">Turn {turn.turn_number} -- response</div>
              <pre className="code-block">{turn.response}</pre>
              <div className="transcript-meta">latency: {turn.latency_ms.toFixed(0)}ms</div>
            </li>
          ))}
        </ol>
      )}

      {test.findings.length > 0 && (
        <>
          <h2>Findings</h2>
          <ul>
            {test.findings.map((finding, index) => (
              <li key={index}>
                <strong>{finding.severity}</strong> [{finding.owasp_category}]: {finding.description}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
