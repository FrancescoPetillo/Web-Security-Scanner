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
    "⚙️ Finalizing analysis...",
  ];

  function normalizeUrl(input) {
    const trimmed = input.trim();

    if (!trimmed) {
      throw new Error("URL vuoto");
    }

    const withProtocol =
      trimmed.startsWith("http://") || trimmed.startsWith("https://")
        ? trimmed
        : `https://${trimmed}`;

    const parsed = new URL(withProtocol);

    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error("Protocollo non valido");
    }

    if (!parsed.hostname) {
      throw new Error("Host non valido");
    }

    return parsed.toString();
  }

  async function handleScan() {
    let safeUrl;

    try {
      safeUrl = normalizeUrl(url);
    } catch {
      alert("Inserisci un URL valido");
      return;
    }

    setLoading(true);

    let i = 0;
    const interval = setInterval(() => {
      i++;
      setStep(i % steps.length);
    }, 800);

    try {
      const res = await fetch(
        `http://localhost:8000/scan?url=${encodeURIComponent(safeUrl)}`,
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
    } finally {
      setLoading(false);
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
            disabled={loading}
          />

          {!loading && (
            <button className="scan-button" onClick={handleScan}>
              Avvia analisi
            </button>
          )}
        </div>

        {loading && (
          <div className="loading-box">
            <p className="loading-text">{steps[step]}</p>
          </div>
        )}
      </div>
    </div>
  );
}

export default Home;