import { useState } from "react";
import { useNavigate } from "react-router-dom";

function Home() {
  const [url, setUrl] = useState("");
  const navigate = useNavigate();

  async function handleScan() {
    try {
      const res = await fetch(
        `http://localhost:8000/scan?url=${encodeURIComponent(url)}`,
        { method: "POST" }
      );

      const data = await res.json();
      console.log(data);

      navigate("/results", { state: data });
    } catch (err) {
      navigate("/results", {
        state: {
          status: "error",
          error: err.message,
        },
      });
    }
  }

  return (
    <div style={{ textAlign: "center", marginTop: "100px" }}>
      <h1>Web Security Scanner</h1>

      <input
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="Inserisci URL..."
        style={{ padding: "12px", width: "320px" }}
      />

      <br /><br />

      <button onClick={handleScan} style={{ padding: "12px 24px" }}>
        Avvia analisi
      </button>
    </div>
  );
}

export default Home;