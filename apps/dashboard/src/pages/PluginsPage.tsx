import { useEffect, useState } from "react";
import { ApiError, fetchPlugins } from "../api/client";
import type { PluginsResponse } from "../types";

const GROUP_LABELS: Record<string, string> = {
  "cyberjection.mutators": "Mutators",
  "cyberjection.strategies": "Strategies",
  "cyberjection.evaluators": "Evaluators",
  "cyberjection.exporters": "Exporters",
};

export default function PluginsPage() {
  const [data, setData] = useState<PluginsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchPlugins()
      .then((response) => {
        if (!cancelled) setData(response);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "Failed to load plugins.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return <div className="panel panel-error">{error}</div>;
  }

  if (data === null) {
    return <div className="panel">Loading plugins...</div>;
  }

  return (
    <div className="panel">
      <h1>Plugins</h1>
      <p>
        Every registered mutator, single-turn strategy, evaluator, and report exporter alias --
        built-in and third-party (discovered via Python entry points; see{" "}
        <code>cyberjection.plugins.loader</code>).
      </p>

      {data.failures.length > 0 && (
        <div className="panel-error">
          <strong>{data.failures.length} plugin(s) failed to load:</strong>
          <ul>
            {data.failures.map((failure, index) => (
              <li key={index}>{failure}</li>
            ))}
          </ul>
        </div>
      )}

      {Object.entries(data.registered).map(([group, aliases]) => (
        <section key={group}>
          <h2>{GROUP_LABELS[group] ?? group}</h2>
          {aliases.length === 0 ? (
            <p>None registered.</p>
          ) : (
            <div className="chip-row">
              {aliases.map((alias) => (
                <span key={alias} className="chip">
                  {alias}
                </span>
              ))}
            </div>
          )}
        </section>
      ))}

      {data.discovered.length > 0 && (
        <>
          <h2>Discovered this run</h2>
          <table className="data-table">
            <thead>
              <tr>
                <th>Group</th>
                <th>Alias</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {data.discovered.map((plugin) => (
                <tr key={`${plugin.group}:${plugin.alias}`}>
                  <td>{GROUP_LABELS[plugin.group] ?? plugin.group}</td>
                  <td>{plugin.alias}</td>
                  <td>{plugin.qualified_name}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}
