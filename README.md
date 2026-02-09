# Glamdring - Standalone Malware Analyzer

A lightweight, standalone malware analysis tool for local use - **no login required!**

## Features

- 🛡️ **Static Analysis**: Hash calculation, string extraction, entropy analysis
- 🔍 **File Type Detection**: Identifies PE, ELF, PDF, ZIP, and more
- 📊 **Threat Scoring**: Automated 0-100 risk assessment
- 🎯 **Interesting String Detection**: Extracts URLs, IPs, registry keys, file paths
- 💾 **SQLite Database**: Lightweight local storage
- 🎨 **Modern UI**: Dark-themed React interface
- 🚀 **Standalone**: Single-user, local execution
- 🐳 **Dockerized**: Easy container deployment

## 🚀 Deployment Options

### Option 1: Standalone EXE (Windows)
The easiest way to run Glamdring. No installation required.

1.  Run rebuild.bat to build .exe (this needs to be ran everytime changes are made to rebuild your .exe)
2.  Locate **`Glamdring.exe`** in the `dist/` folder.
3.  Double-click to run.
4.  The console will open, and your browser will launch automatically.

**Note**: The first run might take a few seconds to extract temporary files.

### Option 2: Docker (Any OS)
Run Glamdring in an isolated container.

1.  **Build and Run**:
    ```powershell
    docker-compose up -d
    ```
2.  **Access**:
    Open http://localhost:8000
3.  **Stop**:
    ```powershell
    docker-compose down
    ```

**Data Persistence**:
Data is stored in a Docker volume (`glamdring_data`). To reset everything:
```powershell
docker-compose down -v
```

### Option 3: Python Source (Developers)
### Installation

1. **Install dependencies**:
```powershell
pip install fastapi uvicorn sqlalchemy python-multipart httpx python-dotenv pydantic-settings
```

2. **Run the application**:
```powershell
python malware_analyzer.py
```

The app will automatically:
- Start the backend server on localhost:8000
- Open your browser to the UI
- Create necessary directories in `~/.malware-analyzer/`

### First Use

1. **Upload a file**: Click "Upload Sample" on the dashboard
2. **Analyze**: Click "Analyze" button on any sample
3. **View Results**: See hashes, strings, entropy, and threat score

## Analysis Capabilities

### Currently Implemented ✅

- **Hash Calculation**: MD5, SHA1, SHA256
- **File Information**: Size, type, magic bytes
- **String Extraction**: ASCII and Unicode strings
- **Interesting Strings**: URLs, IPs, emails, registry keys, file paths, crypto keywords
- **Entropy Analysis**: Detects encryption/packing (0-8 scale)
- **File Type Detection**: PE, ELF, ZIP, RAR, PDF, Office documents
- **Threat Scoring**: Automated 0-100 risk assessment

### Example Analysis Output

```json
{
  "hashes": {
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706..."
  },
  "file_info": {
    "filename": "sample.exe",
    "size_bytes": 45056,
    "size_kb": 44.0,
    "size_mb": 0.04
  },
  "strings": {
    "total_count": 234,
    "interesting": {
      "urls": ["http://malicious-site.com/payload"],
      "ips": ["192.168.1.100", "10.0.0.5"],
      "registry_keys": ["HKEY_LOCAL_MACHINE\\Software\\..."]
    }
  },
  "entropy": {
    "entropy": 7.2,
    "verdict": "High - Possibly encrypted/compressed"
  },
  "file_type": {
    "type": "PE",
    "description": "Windows Executable (PE/EXE/DLL)"
  }
}
```

## Project Structure

```
malware-analyzer/
├── backend/
│   ├── main.py              # FastAPI application
│   ├── analyzer.py          # Static analysis engine
│   ├── models.py            # SQLAlchemy models
│   ├── database.py          # SQLite connection
│   ├── config.py            # Settings
│   └── requirements.txt     # Python dependencies
├── frontend/
│   └── src/
│       ├── pages/           # React pages
│       ├── api/             # API client
│       └── App.tsx          # Main app
├── malware_analyzer.py      # One-click launcher
└── README.md
```

## Data Storage

All data is stored locally in `~/.malware-analyzer/`:

- **local.db**: SQLite database (samples, analyses)
- **samples/**: Uploaded malware files (named by SHA256)

## API Endpoints

All endpoints accessible at http://localhost:8000

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/docs` | GET | Swagger API documentation |
| `/api/samples/upload` | POST | Upload file for analysis |
| `/api/samples` | GET | List all samples |
| `/api/samples/{id}` | GET | Get sample details |
| `/api/samples/{id}` | DELETE | Delete sample |
| `/api/analysis/{id}/start` | POST | Start static analysis |
| `/api/analysis/{id}` | GET | Get analysis results |

## Configuration

Optional `.env` file in the `backend/` directory:

```env
VT_API_KEY=your_virustotal_api_key_here
MAX_UPLOAD_SIZE=104857600  # 100MB
```

## Security Note

⚠️ **WARNING**: This tool handles potentially malicious files. Always run in an isolated environment or sandbox.

- Binds to localhost only (127.0.0.1)
- No network exposure by default
- Files stored in isolated directory

## Threat Score Algorithm

The threat score (0-100) is calculated based on:

- **Entropy** (40 points max): High entropy suggests encryption/packing
- **Interesting Strings** (30 points max): URLs, IPs, registry modifications, crypto usage
- **File Type** (20 points max): Executable files score higher
- **File Size** (10 points max): Unusually small executables are suspicious

## Requirements

- Python 3.11+
- Windows/Linux/macOS
- 100MB+ free disk space

## Troubleshooting

**"Module not found" errors**:
```powershell
pip install fastapi uvicorn sqlalchemy python-multipart httpx python-dotenv pydantic-settings
```

**Port 8000 already in use**:
Edit `backend/config.py` and change `PORT = 8000` to another port.

**Analysis fails**:
Check that the file exists and is readable. View logs in the terminal.

## Development

The server uses hot-reload, so changes to backend code automatically refresh:

1. Edit `backend/main.py` or `backend/analyzer.py`
2. Save the file
3. Server reloads automatically
4. Test changes immediately

## Future Enhancements

- Report generation (PDF/HTML)

## License

MIT License - see LICENSE file for details

## Credits

Built with:
- FastAPI - Web framework
- React - Frontend UI
- SQLAlchemy - Database ORM
- SQLite - Local database

---

**No login required - just run and analyze!** 🛡️

---

**Please note this is a work in progress program and in no way should be solely relied on for determining if a file is truly malware. It is intended for quick judgement and should be investigated further with other tools**
