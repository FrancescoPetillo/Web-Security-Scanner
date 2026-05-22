import { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Home.css";

function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);

  const navigate = useNavigate();

  const steps = [
    "🔍 Scanning URL...",
    "🔐 Checking HTTPS...",
    "🍪 Analyzing cookies...",
    "🛡️ Inspecting security headers...",
    "⚙️ Finalizing analysis..."
  ];

  async function handleScan() {
    if (!url) return;

    setLoading(true);

    let i = 0;
    const interval = setInterval(() => {
      i++;
      setStep(i % steps.length);
    }, 800);

    try {
      const res = await fetch(
        `http://localhost:8000/scan?url=${encodeURIComponent(url)}`,
        { method: "POST" }
      );

      const data = await res.json();

      clearInterval(interval);
      navigate("/results", { state: data });

    } catch (err) {
      clearInterval(interval);

      navigate("/results", {
        state: {
          status: "error",
          error: err.message,
        },
      });
    }
  }

  return (
    <div className="home-container">
      <div className="home-hero">
        <h1 className="tech-title">Web Security Scanner</h1>

        <p className="tech-subtitle">
          Analisi automatizzata, precisione enterprise.
        </p>

        <div className="scan-form">
          <input
            className="scan-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
          />

          {!loading && (
            <button className="scan-button" onClick={handleScan} aria-label="Avvia analisi di sicurezza">
              <span className="scan-button__halo" />
              <span className="scan-button__icon" aria-hidden="true" />
              <span className="scan-button__text">Avvia analisi</span>
            </button>
          )}
        </div>

        {loading && (
          <div className="loading-box">
            <p className="loading-text">{steps[step]}</p>
          </div>
        )}
      </div>

      <p className="home-credit">
        Ideato e sviluppato da Francesco Petillo e Gabriele Esposito.
      </p>
    </div>
  );
}

export default Home;
