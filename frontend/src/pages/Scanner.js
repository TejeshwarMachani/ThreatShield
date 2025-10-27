import { useState, useCallback } from "react";
import axios from "axios";
import { Shield, Upload, AlertTriangle, CheckCircle, XCircle, FileText, Hash, Calendar, TrendingUp } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Scanner = () => {
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setScanResult(null);
    }
  }, []);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setScanResult(null);
    }
  };

  const scanFile = async () => {
    if (!file) {
      toast.error("Please select a file to scan");
      return;
    }

    setScanning(true);
    setScanResult(null);
    setUploadProgress(0);

    try {
      const formData = new FormData();
      formData.append("file", file);

      // Simulate upload progress
      const progressInterval = setInterval(() => {
        setUploadProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 200);

      const response = await axios.post(`${API}/scan`, formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      clearInterval(progressInterval);
      setUploadProgress(100);

      setScanResult(response.data);
      
      if (response.data.threat_level === "safe") {
        toast.success("File is safe!");
      } else if (response.data.threat_level === "caution") {
        toast.warning("Proceed with caution");
      } else if (response.data.threat_level === "suspicious") {
        toast.warning("Suspicious file detected!");
      } else {
        toast.error("Malware detected!");
      }
    } catch (error) {
      console.error("Scan error:", error);
      toast.error("Failed to scan file. Please try again.");
    } finally {
      setScanning(false);
      setTimeout(() => setUploadProgress(0), 1000);
    }
  };

  const getThreatIcon = (level) => {
    switch (level) {
      case "safe":
        return <CheckCircle className="w-16 h-16 text-emerald-400" />;
      case "caution":
        return <AlertTriangle className="w-16 h-16 text-yellow-400" />;
      case "suspicious":
        return <AlertTriangle className="w-16 h-16 text-orange-400" />;
      case "malicious":
        return <XCircle className="w-16 h-16 text-red-400" />;
      default:
        return <Shield className="w-16 h-16 text-gray-400" />;
    }
  };

  const getThreatColor = (level) => {
    switch (level) {
      case "safe":
        return "text-emerald-400";
      case "caution":
        return "text-yellow-400";
      case "suspicious":
        return "text-orange-400";
      case "malicious":
        return "text-red-400";
      default:
        return "text-gray-400";
    }
  };

  const getThreatBg = (level) => {
    switch (level) {
      case "safe":
        return "bg-emerald-500/10";
      case "caution":
        return "bg-yellow-500/10";
      case "suspicious":
        return "bg-orange-500/10";
      case "malicious":
        return "bg-red-500/10";
      default:
        return "bg-gray-500/10";
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  };

  return (
    <div className="scanner-container">
      {/* Header */}
      <div className="header-section">
        <div className="shield-icon-wrapper">
          <Shield className="shield-icon" />
        </div>
        <h1 className="main-title">ThreatShield</h1>
        <p className="subtitle">Advanced Malware Detection & Analysis</p>
      </div>

      {/* Upload Section */}
      <div className="upload-section">
        <Card className="upload-card" data-testid="upload-card">
          <div
            className={`dropzone ${dragActive ? "dropzone-active" : ""}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            data-testid="file-dropzone"
          >
            <Upload className="upload-icon" />
            <h3 className="dropzone-title">Drop your file here</h3>
            <p className="dropzone-text">or click to browse</p>
            <input
              type="file"
              onChange={handleFileChange}
              className="file-input"
              data-testid="file-input"
            />
          </div>

          {file && (
            <div className="file-info" data-testid="selected-file-info">
              <FileText className="w-5 h-5 text-cyan-400" />
              <span className="file-name" data-testid="file-name">{file.name}</span>
              <span className="file-size" data-testid="file-size">({formatFileSize(file.size)})</span>
            </div>
          )}

          <Button
            onClick={scanFile}
            disabled={!file || scanning}
            className="scan-button"
            data-testid="scan-button"
          >
            {scanning ? (
              <>
                <div className="spinner" />
                Scanning...
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                Scan File
              </>
            )}
          </Button>

          {scanning && uploadProgress > 0 && (
            <div className="progress-container" data-testid="scan-progress">
              <Progress value={uploadProgress} className="scan-progress" />
              <span className="progress-text">{uploadProgress}%</span>
            </div>
          )}
        </Card>
      </div>

      {/* Results Section */}
      {scanResult && (
        <div className="results-section" data-testid="scan-results">
          <Card className="result-card">
            <div className={`threat-header ${getThreatBg(scanResult.threat_level)}`}>
              <div className="threat-icon-container">
                {getThreatIcon(scanResult.threat_level)}
              </div>
              <h2 className={`threat-title ${getThreatColor(scanResult.threat_level)}`} data-testid="threat-level">
                {scanResult.threat_level.toUpperCase()}
              </h2>
              <p className="threat-subtitle">Threat Assessment Complete</p>
            </div>

            <div className="result-details">
              <div className="detail-grid">
                <div className="detail-item">
                  <div className="detail-icon">
                    <FileText className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <p className="detail-label">Filename</p>
                    <p className="detail-value" data-testid="result-filename">{scanResult.filename}</p>
                  </div>
                </div>

                <div className="detail-item">
                  <div className="detail-icon">
                    <TrendingUp className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <p className="detail-label">File Size</p>
                    <p className="detail-value" data-testid="result-filesize">{formatFileSize(scanResult.file_size)}</p>
                  </div>
                </div>

                <div className="detail-item">
                  <div className="detail-icon">
                    <FileText className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <p className="detail-label">File Type</p>
                    <p className="detail-value" data-testid="result-filetype">{scanResult.file_type}</p>
                  </div>
                </div>

                <div className="detail-item">
                  <div className="detail-icon">
                    <TrendingUp className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <p className="detail-label">Risk Score</p>
                    <p className="detail-value" data-testid="result-risk-score">{scanResult.heuristic_score}/100</p>
                  </div>
                </div>
              </div>

              <div className="hash-section">
                <div className="hash-item">
                  <Hash className="w-4 h-4 text-cyan-400" />
                  <span className="hash-label">MD5:</span>
                  <code className="hash-value" data-testid="result-md5">{scanResult.md5_hash}</code>
                </div>
                <div className="hash-item">
                  <Hash className="w-4 h-4 text-cyan-400" />
                  <span className="hash-label">SHA256:</span>
                  <code className="hash-value" data-testid="result-sha256">{scanResult.sha256_hash}</code>
                </div>
              </div>

              <div className="threats-section">
                <h3 className="threats-title">Threat Analysis</h3>
                <div className="threats-list" data-testid="threats-list">
                  {scanResult.threats_detected.map((threat, index) => (
                    <div key={index} className="threat-item" data-testid={`threat-item-${index}`}>
                      <div className="threat-bullet" />
                      <span>{threat}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </Card>
        </div>
      )}

      {/* Footer */}
      <div className="footer">
        <p>Powered by advanced heuristic analysis & threat intelligence</p>
      </div>
    </div>
  );
};

export default Scanner;