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

    // aggiungi protocollo se manca
    const withProtocol =
      trimmed.startsWith("http://") || trimmed.startsWith("https://")
        ? trimmed
        : `https://${trimmed}`;

    const parsed = new URL(withProtocol);

    // controllo dominio valido (minimo)
    if (!parsed.hostname.includes(".")) {
      throw new Error("Dominio non valido");
    }

    return parsed.toString();
  }

  async function handleScan() {
    let safeUrl;

    try {
      safeUrl = normalizeUrl(url);
    } catch (err) {
      alert(err.message);
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
        "https://web-security-scanner-production.up.railway.app/scan", // ✅ FIX QUI
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ url: safeUrl }),
        }
      );

      if (!res.ok) {
        throw new Error(`Errore server (${res.status})`);
      }

      const data = await res.json();

      navigate("/results", { state: data });

    } catch (err) {
      navigate("/results", {
        state: {
          status: "error",
          error: err.message || "Errore sconosciuto",
        },
      });
    } finally {
      clearInterval(interval);
      setLoading(false);
    }
  }

  return (
    <div className="home-container">
      <div className="home-hero">
        <h1 className="tech-title">Web Security Scanner</h1>

        <p className="tech-subtitle">
          Scan. Detect. Secure.
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

      <div className="home-credit" aria-label="Ideato e sviluppato da Francesco Petillo e Gabriele Esposito">
        <span className="home-credit__label">Ideato e sviluppato da</span>
        <span className="home-credit__names">Francesco Petillo e Gabriele Esposito</span>
      </div>
    </div>
  );
}

export default Home;
