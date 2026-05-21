function App() {
  return (
    <div style={{ textAlign: "center", marginTop: "100px" }}>
      <h1>Web Security Scanner</h1>

      <input placeholder="Inserisci URL..." style={{ padding: "10px", width: "300px" }} />

      <br /><br />

      <button style={{ padding: "10px 20px" }}>
        Avvia scansione
      </button>
    </div>
  );
}

export default App;