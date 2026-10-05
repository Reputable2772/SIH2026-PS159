# SecureMailScope — Forensic Investigation Workbench UI

The frontend for **SecureMailScope** is a high-fidelity, interactive cybersecurity forensic dashboard built with React and Vite. It directly reproduces the dark cybersecurity forensic theme from the reference mockups in `frontend_mockup/`.

---

## 🛠 Technology Stack

- **Framework**: [React 19](https://react.dev/) + [Vite 8](https://vite.dev/)
- **Routing**: [React Router v7](https://reactrouter.com/)
- **Styling**: Native CSS Design System (`src/index.css`) with curated cybersecurity forensic palette
- **Icons**: [Lucide React](https://lucide.dev/) (`lucide-react`)
- **Visualizations**: Custom SVG Donut Gauge, SVG Activity Timeline Chart, SVG 2D Anomaly Scatter Plot, Handshake Sequence Flow, and Certificate Chain Validation diagram
- **Typography**: [Inter](https://fonts.google.com/specimen/Inter) (Body & Headings) and [JetBrains Mono](https://fonts.google.com/specimen/JetBrains+Mono) (PCAP hashes, packet numbers, timestamps, and IP addresses)

---

## 🚀 Quick Start

### 1. Prerequisites
- **Node.js**: v18+ (tested on Node v22)
- **npm**: v9+

### 2. Installation
From the `frontend/` directory:
```bash
npm install
```
*(Dependencies are already installed in this repository).*

### 3. Development Server
To launch the local Vite development server with Hot Module Replacement (HMR):
```bash
npm run dev
# OR from the repository root:
just frontend
```
The application will be live at:
```
http://localhost:5173/
```

### 4. Production Build
To validate or build the optimized production bundle:
```bash
npm run build
# OR from the repository root:
just frontend-build
```
Build outputs are placed in `frontend/dist/`.

To locally preview the production build:
```bash
npm run preview
```

### 5. Linting
```bash
npm run lint
```

---

## 📐 Page Routes & Mockup Reference

All 8 screens in `frontend_mockup/` are implemented with 1:1 visual fidelity:

| Route | View Name | Reference Mockup | Key Interactive Components |
|---|---|---|---|
| `/` or `/overview` | **Cryptographic Posture** | `Overview.svg` | Donut gauge (40 of 48 encrypted), composite score gauge (`72/100 HIGH`), "Investigate first" triage card, TLS/Cipher/Forward Secrecy bars, Protocol table, and Activity timeline chart. |
| `/findings` | **Prioritized Findings** | `Prioritized findings.svg` | 5 KPI summary boxes, Filter tabs (*All*, *Deterministic*, *ML*), Category/Severity filters, finding row selector, packet-level provenance pane, and analyst recommendations. |
| `/sessions` | **Session Explorer** | `Session explorer.svg` | 4 summary cards, Protocol tabs, search & filters, paginated sessions table with STARTTLS badges, and dual comparison cards (S-017 suspicious fallback vs S-004 validated control). |
| `/sessions/:id` | **Session Forensic Detail** | `Session forensic detail.svg` | Source/Destination banner, TCP stream reconstruction table (#180–#191), Session facts, Evidence-linked findings, side-by-side handshake comparison flow, and Client fingerprint. |
| `/captures` | **Capture Library & Ingestion** | `Capture library & ingestion.svg` | Drag-and-drop PCAP upload zone, server path ingestion form (Async/Sync), available captures table with download actions, selected capture facts, and processing lifecycle jobs. |
| `/anomalies` | **AI Anomalies** | `AI anomalies.svg` | Interactive 2D scatter plot (-0.30 to +0.30 score vs record count) with outlier selection ring, 16-D Isolation Forest model card, scored sessions table, 8-feature breakdown, and evidence separation banner. |
| `/crypto` | **Cryptography & Certificates** | `Cryptography & certificates.svg` | 4 KPI cards, Certificate inventory table, Selected X.509 card with expiration countdown (`-19 · expired at capture time`), and Certificate Chain Validation diagram. |
| `/reports` | **Forensic Reports** | `Forensic reports.svg` | Format selector (JSON, PDF, HTML), standalone HTML report preview with executive summary and evidence manifest, export checklist, and JSON structure preview. |

---

## 🎨 Design System & Color Tokens

Defined in [`src/index.css`](src/index.css):

```css
:root {
  --bg-base: #0D1115;          /* Main workspace background */
  --bg-sidebar: #10161B;       /* Left navigation sidebar */
  --bg-card: #151C22;          /* Card container background */
  --bg-surface: #10171D;       /* Sub-card and table header surface */
  --bg-card-hover: #1B242C;    /* Row and card hover */
  --border-default: #2A353E;   /* Card, table, and panel borders */

  --text-primary: #EDF3F5;     /* High-contrast headings and text */
  --text-secondary: #A5B4BF;   /* Subtitles and neutral table values */
  --text-muted: #778995;       /* Captions, labels, and inactive icons */

  --accent-teal: #59D9BC;      /* Primary mint accent (active pills, charts) */
  --accent-teal-dim: #163A34;  /* Active nav background, badge background */

  --accent-amber: #F3BC68;     /* Warning, High severity, Demo badge */
  --accent-amber-dim: #392F21; /* Demo badge background, High severity background */

  --accent-red: #F48286;       /* Critical severity, errors, expired certs */
  --accent-red-dim: #3B1C1D;   /* Critical badge background */

  --sidebar-width: 224px;      /* Fixed sidebar width matching SVGs */
}
```

---

## 🔌 API & Backend Architecture

The frontend is fully wired to the FastAPI backend and dynamically renders live forensic data across all 8 views.

### Live Backend Integration (Default)
When the FastAPI backend is running (e.g. `just backend` on `http://localhost:8000`), the frontend:
1. Connects to `http://localhost:8000` (proxied natively via Vite dev server at `/api`).
2. Fetches available PCAPs from `/api/pcaps`.
3. Loads full forensic analysis trees from `/api/pcaps/{filename}/analysis` or `/api/analysis/{id}`.
4. Dynamically populates:
   - **Overview**: Posture risk score, encrypted vs cleartext donut gauge, TLS distributions, cipher suites, protocol distribution, and activity timelines.
   - **Prioritized Findings**: Filterable rule findings & ML anomalies with packet provenance coordinates.
   - **Session Explorer**: Reconstructed TCP email conversations with STARTTLS states, TLS handshakes, and risk levels.
   - **Session Detail**: Deep packet stream dissection, banners, and handshake flows.
   - **AI Anomalies**: 16-D Isolation Forest scatter plot and 16-feature vector breakdown.
   - **Cryptography**: X.509 certificate inventory, validity auditing, and certificate chain validation.
   - **Capture Library**: PCAP upload, server file ingestion, and cached analysis runs.
   - **Forensic Reports**: Embedded live HTML report preview (`/report/html`), PDF export (`/report/pdf`), and serialized JSON inspection (`/report/json`).

### Resilient Offline Fallback
If the backend is ever offline or unreachable during a presentation or demo, the application seamlessly falls back to the baseline dataset in [`src/mockData.js`](src/mockData.js), displaying a "Demo data" indicator without crashing.

---

## 📁 Directory Structure

```
frontend/
├── index.html                  # HTML entry point with Inter & JetBrains Mono
├── package.json                # Project dependencies & scripts
├── vite.config.js              # Vite configuration with React plugin
├── src/
│   ├── main.jsx                # Application root entry
│   ├── App.jsx                 # Client router with all 8 page routes
│   ├── index.css               # Complete SecureMailScope Design System
│   ├── api.js                  # FastAPI backend client & helpers
│   ├── mockData.js             # High-fidelity mock dataset matching SVGs
│   ├── components/
│   │   ├── Layout.jsx          # App shell (Sidebar + Topbar + Content)
│   │   ├── Sidebar.jsx         # 224px navigation bar with status footer
│   │   ├── Topbar.jsx          # Breadcrumbs, capture dropdown, new analysis
│   │   ├── FooterNote.jsx      # Assessment limits & passive analysis fineprint
│   │   ├── NewAnalysisModal.jsx# PCAP upload & server file analysis modal
│   │   ├── DonutGauge.jsx      # SVG donut gauge for posture overview
│   │   ├── ActivityChart.jsx   # SVG packet activity timeline chart
│   │   ├── AnomalyScatterPlot.jsx # Interactive 2D Isolation Forest plot
│   │   ├── HandshakeFlow.jsx   # Side-by-side handshake reconstruction
│   │   └── CertificateChain.jsx# Certificate validation chain diagram
│   └── pages/
│       ├── OverviewPage.jsx    # Overview dashboard (/overview)
│       ├── PrioritizedFindingsPage.jsx # Findings queue (/findings)
│       ├── SessionExplorerPage.jsx     # Reconstructed sessions (/sessions)
│       ├── SessionDetailPage.jsx       # Deep session forensic detail (/sessions/:id)
│       ├── CaptureLibraryPage.jsx      # PCAP ingestion library (/captures)
│       ├── AIAnomaliesPage.jsx         # Isolation Forest outliers (/anomalies)
│       ├── CryptographyPage.jsx        # X.509 & cipher inventory (/crypto)
│       └── ForensicReportsPage.jsx     # Forensic export workbench (/reports)
```
