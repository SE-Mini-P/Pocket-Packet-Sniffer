# Pocket Packet Sniffer

Portable WiFi / Ethernet / BLE packet sniffer with a local web dashboard.
See the SRS (PPS-SRS-1.0) for full requirements.

> Status: early development. Hardware capture is **mocked** (`backend/mock_capture.py`).

## Project structure

```
Pocket-Packet-Sniffer/
├── backend/
│   ├── app.py              # Flask app: serves dashboard + /api/status
│   ├── mock_capture.py     # Mock capture service (replace with real capture later)
│   └── requirements.txt
├── frontend/
│   ├── index.html          # Dashboard page
│   ├── css/styles.css
│   └── js/app.js
├── docs/                   # SRS and other documents
├── .gitignore
└── README.md
```

## Run locally

Requires Python 3.10+.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
python backend/app.py
```

Open http://127.0.0.1:5000

### Try different mock states

```bash
# macOS / Linux
PPS_MOCK_STATUS=capturing PPS_MOCK_INTERFACE=eth0 python backend/app.py

# Windows PowerShell
$env:PPS_MOCK_STATUS="capturing"; $env:PPS_MOCK_INTERFACE="eth0"; python backend/app.py
```

Statuses: `idle`, `capturing`, `stopped`, `error`. Interfaces: `wlan0`, `eth0`, `ble0`.

## API

`GET /api/status`

```json
{
  "interface": {"name": "wlan0", "type": "WiFi (802.11 monitor mode)"},
  "capture": {"status": "idle", "started_at": null}
}
```
