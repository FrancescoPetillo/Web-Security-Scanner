import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import "./Results.css";

function Results() {
  const { state } = useLocation();
  const navigate = useNavigate();
  const [scoreFill, setScoreFill] = useState(0);
  const score = Math.max(0, Math.min(Number(state?.score) || 0, 100));
  const riskLevel = state?.risk_level || "Unknown";
  const riskClass = riskLevel.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  const summary = state?.summary;

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      setScoreFill(score);
    });

    return () => cancelAnimationFrame(frame);
  }, [score]);

  if (!state) {
    return (
      <div style={{ color: "white", padding: "40px" }}>
        <h1>Nessun risultato disponibile</h1>
        <button onClick={() => navigate("/")}>Torna alla Home</button>
      </div>
    );
  }

  if (state.status === "error") {
    return (
      <div style={{ color: "white", padding: "40px" }}>
        <button onClick={() => navigate("/")}>← Nuova analisi</button>
        <h1>Errore scansione</h1>
        <p>{state.error}</p>
      </div>
    );
  }

  const grouped = state.grouped_findings || {};

  return (
    <div style={{ color: "white", padding: "40px" }}>
      <button className="new-scan-button" onClick={() => navigate("/")}>
        <span className="new-scan-button__icon" aria-hidden="true">←</span>
        <span>Nuova analisi</span>
      </button>

      <h1>Risultati analisi</h1>

      <p><b>URL:</b> {state.url}</p>
      <p><b>Final URL:</b> {state.final_url}</p>

      <section className={`score-panel score-panel--${riskClass}`}>
        <div className="score-panel__header">
          <div>
            <span className="score-panel__label">Security score</span>
            <strong className="score-panel__value">Score: {score}/100</strong>
          </div>

          <span className="score-panel__risk">Risk: {riskLevel}</span>
        </div>

        <div className="score-meter" aria-label={`Security score ${score} out of 100`}>
          <div
            className="score-meter__fill"
            style={{ width: `${scoreFill}%` }}
          />
        </div>

        <p className="score-panel__description">{state.risk_explanation}</p>

        {summary && (
          <div className="score-summary">
            <p>{summary.message}</p>
            <div className="score-summary__stats">
              <span>{summary.vulnerabilities} vulnerabilities</span>
              <span>{summary.hardening} hardening</span>
              <span>{summary.reputation_status}</span>
            </div>
          </div>
        )}
      </section>

      {Object.entries(grouped).map(([category, findings]) => (
        <section key={category} className="findings-section">
          <div className="findings-section__header">
            <h2>{category.toUpperCase()}</h2>
            <span>{findings.length}</span>
          </div>

          {findings.length === 0 && (
            <p className="findings-section__empty">Nessun problema rilevato</p>
          )}

          {findings.map((f, i) => {
            const severity = f.severity || "Low";
            const severityClass = severity.toLowerCase().replace(/[^a-z0-9]+/g, "-");

            return (
              <div
                key={i}
                className={`finding-card finding-card--${severityClass}`}
              >
                <div className="finding-card__top">
                  <h3>{f.title}</h3>
                  <span>{severity}</span>
                </div>

                <div className="finding-card__meta">
                  <span>{f.type || "finding"}</span>
                  <span>Confidence: {f.confidence || "medium"}</span>
                  <span>Impact: {f.impact || "moderate"}</span>
                </div>

                <p className="finding-card__description">{f.description}</p>

                <div className="finding-card__recommendation">
                  <span>Recommendation</span>
                  <small>{f.recommendation}</small>
                </div>
              </div>
            );
          })}
        </section>
      ))}
    </div>
  );
}

export default Results;
