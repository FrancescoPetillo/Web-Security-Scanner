# 🛡️ Web Security Scanner

Un'applicazione moderna per analizzare la sicurezza di siti web. Rileva vulnerabilità, controlla i header di sicurezza, valuta la reputazione del dominio e fornisce raccomandazioni di hardening.

## ✨ Funzionalità

- **Scansione Header HTTP** - Verifica la presenza di header di sicurezza critici (CSP, HSTS, etc.)
- **Scoring Intelligente** - Calcolo dinamico della sicurezza basato su vulnerabilità e configurazione
- **Analisi Reputazione** - Verifica se il dominio è segnalato come malevolo o sospetto
- **Riporto Dettagliato** - Report completo con categorie di vulnerabilità e raccomandazioni
- **Interfaccia Intuitiva** - Dashboard React moderna e responsive

## 🖼️ Anteprima

### Home
Schermata iniziale dell'applicazione, dove inserire l'URL da analizzare e avviare la scansione.

![Home Web Security Scanner](./Screenshot%202026-05-27%20020418.png)

### Risultati analisi
Report generato dopo la scansione, con score di sicurezza, livello di rischio e findings rilevati.

![Risultati analisi Web Security Scanner](./Screenshot%202026-05-27%20020535.png)

## 🏗️ Architettura

```
Web-Security-Scanner/
├── frontend/              # React + Vite + React Router
│   ├── src/
│   │   ├── pages/        # Home (input URL) e Results (report)
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
│
├── backend/               # FastAPI + Python
│   ├── main.py           # Server FastAPI con endpoint /scan
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── scanner/
│   │   ├── engine.py     # Logica principale di scansione
│   │   ├── scoring.py    # Calcolo score di sicurezza
│   │   ├── reputation.py # Verifica reputazione dominio
│   │   └── ...
│   └── venv/
│
├── engine.py             # Entry point principale
└── README.md
```

## 🚀 Quick Start

### Prerequisites
- **Node.js** 18+ (per il frontend)
- **Python** 3.10+ (per il backend)
- **Docker** (opzionale, consigliato)

### Installazione Locale

#### 1️⃣ Backend
```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

#### 2️⃣ Frontend
```bash
cd frontend
npm install
```

#### 3️⃣ Avviare l'applicazione

**Terminal 1 - Backend:**
```bash
cd backend
source venv/bin/activate  # o venv\Scripts\activate su Windows
uvicorn main:app --reload --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd frontend
npm run dev
```

L'app sarà disponibile su `http://localhost:5173`

### Installazione con Docker

```bash
docker build -t web-security-scanner ./backend
docker run -p 8000:8000 web-security-scanner
```

## 📡 API Endpoints

### POST `/scan`
Avvia una scansione di sicurezza su un URL.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "status": "done",
  "url": "https://example.com",
  "score": 85,
  "risk_level": "medium",
  "summary": {
    "message": "No critical vulnerabilities detected...",
    "vulnerabilities": 2,
    "hardening": 3,
    "reputation_status": "Reputation clean"
  },
  "findings": [
    {
      "title": "Missing CSP",
      "type": "hardening",
      "category": "headers",
      "severity": "Medium",
      "confidence": "low"
    }
  ],
  "reputation": {
    "malicious": 0,
    "suspicious": 0
  }
}
```

### GET `/`
Health check endpoint.

## 🎯 Categorie di Findings

### Vulnerabilità (Vulnerability)
Problemi di sicurezza confermati che richiedono correzione immediata.

### Hardening (Hardening)
Configurazioni e best practice raccomandate per migliorare la sicurezza.

## 📊 Risk Levels

- 🟢 **Low** - Score 80-100: Configurazione sicura
- 🟡 **Medium** - Score 50-79: Miglioramenti consigliati
- 🔴 **High** - Score <50: Vulnerabilità critiche rilevate

## 🛠️ Stack Tecnologico

### Backend
- **FastAPI** - Framework web async
- **Pydantic** - Validazione dati
- **Playwright** - Web automation
- **Requests** - HTTP client
- **Uvicorn** - ASGI server

### Frontend
- **React** 19.2 - UI library
- **Vite** - Build tool
- **React Router** - Client-side routing
- **ESLint** - Code linting

## 📝 Sviluppo

### Linting Frontend
```bash
cd frontend
npm run lint
```

### Build Frontend
```bash
cd frontend
npm run build
```

### Format Codice
Il progetto segue le convenzioni PEP8 per Python e ESLint per JavaScript.

## 🔐 Sicurezza

- ⚠️ CORS aperto in fase di debug - da configurare in produzione
- Validazione URL lato server
- Gestione eccezioni robusta
- Timeouts su richieste HTTP

## 🐛 Troubleshooting

### Errore: "CORS not allowed"
Assicurati che il backend sia in esecuzione su `http://localhost:8000`

### Port già in uso
```bash
# Frontend (cambia porta)
npm run dev -- --port 5174

# Backend
uvicorn main:app --port 8001
```

### Import errors Python
```bash
pip install --upgrade -r backend/requirements.txt
```

## 📦 Build per Produzione

```bash
# Frontend
cd frontend
npm run build
# Output in: frontend/dist/

# Backend
# Usa il Dockerfile fornito o deployment preferito
```

## 🤝 Contributi

Segnalazioni bug e suggerimenti sono benvenuti!

## 📄 Licenza

Questo progetto è fornito così com'è per scopi educativi e di security testing autorizzato.

---

**Versione:** 0.0.0  
**Ultimo aggiornamento:** Maggio 2026  
**Autore:** Francesco
