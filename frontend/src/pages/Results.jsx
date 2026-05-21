import { useLocation, useNavigate } from "react-router-dom";

function Results() {
  const { state } = useLocation();
  const navigate = useNavigate();

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
      <button onClick={() => navigate("/")}>← Nuova analisi</button>

      <h1>Risultati analisi</h1>

      <p><b>URL:</b> {state.url}</p>
      <p><b>Final URL:</b> {state.final_url}</p>

      <h2>Score: {state.score}/100</h2>
      <h3>Risk: {state.risk_level}</h3>
      <p>{state.risk_explanation}</p>

      {Object.entries(grouped).map(([category, findings]) => (
        <div key={category} style={{ marginTop: "30px" }}>
          <h2>{category.toUpperCase()} ({findings.length})</h2>

          {findings.length === 0 && <p>Nessun problema rilevato</p>}

          {findings.map((f, i) => (
            <div
              key={i}
              style={{
                border: "1px solid #444",
                borderLeft: `6px solid ${
                  f.severity === "High"
                    ? "red"
                    : f.severity === "Medium"
                    ? "orange"
                    : "green"
                }`,
                padding: "12px",
                marginTop: "10px",
              }}
            >
              <h3>{f.title}</h3>
              <p>{f.description}</p>
              <small>{f.recommendation}</small>
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

export default Results;