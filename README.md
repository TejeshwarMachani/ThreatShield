# 🛡️ ThreatShield

**Advanced Malware Detection & Analysis Platform**

A modern, web-based file security scanner that uses advanced heuristic analysis to detect malicious files, suspicious patterns, and potential threats.

![ThreatShield](https://img.shields.io/badge/Security-Scanner-06b6d4?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)

---

## ✨ Features

### 🔍 Advanced Scanning
- **Heuristic Analysis**: Deep pattern recognition for threat detection
- **File Signature Detection**: Identifies known malware using MD5/SHA256 hashes
- **Suspicious Pattern Detection**: Scans for malicious code patterns
- **Multi-Format Support**: Analyzes all file types (executables, scripts, documents, etc.)

### 🎨 Beautiful UI
- Modern cybersecurity-themed design
- Smooth animations and transitions
- Drag-and-drop file upload
- Real-time scanning progress
- Responsive across all devices

### 📊 Comprehensive Reports
- Threat level classification (Safe/Caution/Suspicious/Malicious)
- File hash generation (MD5, SHA256)
- File type detection
- Risk score calculation (0-100)
- Detailed threat list

### 💾 Scan History
- Persistent storage of scan results
- MongoDB-powered data management
- Quick access to previous scans

---

## 🚀 Tech Stack

### Backend
- **FastAPI** - High-performance Python web framework
- **Motor** - Async MongoDB driver
- **python-magic** - File type detection
- **filetype** - MIME type identification
- **hashlib** - Cryptographic hash generation

### Frontend
- **React 19** - Modern UI library
- **Tailwind CSS** - Utility-first styling
- **Shadcn/UI** - High-quality components
- **Lucide React** - Beautiful icons
- **Axios** - HTTP client
- **Sonner** - Toast notifications

### Database
- **MongoDB** - NoSQL document database

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- Node.js 16+
- MongoDB
- Yarn package manager

### Backend Setup

```bash
# Navigate to backend directory
cd backend

# Install Python dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your MongoDB connection details

# Run the server
uvicorn server:app --reload --host 0.0.0.0 --port 8001
```

### Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
yarn install

# Configure environment variables
cp .env.example .env
# Set REACT_APP_BACKEND_URL to your backend URL

# Start development server
yarn start
```

---

## 🔧 Configuration

### Backend Environment Variables

```env
MONGO_URL=mongodb://localhost:27017
DB_NAME=threatshield_db
CORS_ORIGINS=*
```

### Frontend Environment Variables

```env
REACT_APP_BACKEND_URL=http://localhost:8001
```

---

## 📖 Usage

1. **Upload a File**
   - Drag and drop a file onto the upload zone
   - Or click to browse and select a file

2. **Scan**
   - Click the "Scan File" button
   - Wait for analysis to complete

3. **Review Results**
   - View threat level and risk score
   - Check detected threats
   - Examine file hashes and metadata

---

## 🔌 API Endpoints

### `GET /api/`
Health check endpoint

**Response:**
```json
{
  "message": "ThreatShield API - Malware Scanner"
}
```

### `POST /api/scan`
Scan an uploaded file

**Request:**
- Method: `POST`
- Content-Type: `multipart/form-data`
- Body: `file` (binary)

**Response:**
```json
{
  "id": "uuid",
  "filename": "test.exe",
  "file_size": 1024,
  "file_type": "application/x-executable",
  "md5_hash": "5d41402abc4b2a76b9719d911017c592",
  "sha256_hash": "2c26b46b68ffc68ff99b453c1d30413413422d706...",
  "threat_level": "suspicious",
  "threats_detected": ["Suspicious file extension: .exe"],
  "heuristic_score": 30,
  "scan_timestamp": "2025-01-27T12:00:00Z"
}
```

### `GET /api/scan-history`
Retrieve recent scan history

**Response:**
```json
[
  {
    "id": "uuid",
    "filename": "document.pdf",
    "threat_level": "safe",
    ...
  }
]
```

---

## 🎯 Threat Detection Logic

### Risk Score Calculation

| Factor | Points |
|--------|--------|
| Suspicious file extension (.exe, .dll, .bat, etc.) | +30 |
| Unusually large file (>100MB) | +10 |
| Unusually small file (<10 bytes) | +5 |
| Suspicious code patterns | +20 |
| Binary content in text file | +25 |
| Windows executable detected | +15 |

### Threat Levels

- **Safe** (0 points): No threats detected
- **Caution** (1-49 points): Minor concerns
- **Suspicious** (50-99 points): Multiple red flags
- **Malicious** (Hash match): Known malware signature

---

## 🔮 Future Enhancements

- [ ] VirusTotal API integration
- [ ] Machine learning-based detection
- [ ] Batch file scanning
- [ ] User authentication & accounts
- [ ] Detailed scan reports (PDF export)
- [ ] Real-time threat intelligence feeds
- [ ] Quarantine functionality
- [ ] Email scanning
- [ ] URL reputation checking

---

## 🛠️ Development

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend tests
cd frontend
yarn test
```

### Code Quality

```bash
# Python linting
ruff check .

# JavaScript linting
eslint src/
```

---

## 📸 Screenshots

### Main Interface
Clean, modern design with intuitive file upload

### Scan Results
Comprehensive threat analysis with visual indicators

### Responsive Design
Works seamlessly on desktop, tablet, and mobile

---

## ⚠️ Disclaimer

**ThreatShield is for educational and security research purposes.**

- Not a replacement for professional antivirus solutions
- Heuristic analysis may produce false positives/negatives
- Always use multiple layers of security
- Keep your system and antivirus software updated

---

## 📄 License

MIT License - feel free to use this project for learning and development.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 💬 Support

For issues, questions, or suggestions, please open an issue on the repository.

---

**Built with ❤️ using FastAPI, React, and MongoDB**
