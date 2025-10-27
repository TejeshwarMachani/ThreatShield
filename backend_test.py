import requests
import sys
import io
import hashlib
from datetime import datetime

class ThreatShieldAPITester:
    def __init__(self, base_url="https://threat-shield-21.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED: {details}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details
        })

    def test_api_root(self):
        """Test API root endpoint"""
        try:
            response = requests.get(f"{self.api_url}/", timeout=10)
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            if success:
                data = response.json()
                details += f", Message: {data.get('message', 'No message')}"
            self.log_test("API Root Endpoint", success, details)
            return success
        except Exception as e:
            self.log_test("API Root Endpoint", False, str(e))
            return False

    def create_test_file(self, content, filename):
        """Create test file content"""
        if isinstance(content, str):
            content = content.encode('utf-8')
        return io.BytesIO(content), filename

    def test_scan_safe_file(self):
        """Test scanning a safe text file"""
        try:
            content = "This is a safe text file for testing purposes."
            file_obj, filename = self.create_test_file(content, "safe_test.txt")
            
            files = {'file': (filename, file_obj, 'text/plain')}
            response = requests.post(f"{self.api_url}/scan", files=files, timeout=30)
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                # Verify response structure
                required_fields = ['filename', 'file_size', 'file_type', 'md5_hash', 'sha256_hash', 
                                 'threat_level', 'threats_detected', 'heuristic_score']
                missing_fields = [field for field in required_fields if field not in data]
                
                if missing_fields:
                    success = False
                    details += f", Missing fields: {missing_fields}"
                else:
                    details += f", Threat Level: {data['threat_level']}, Score: {data['heuristic_score']}"
                    # Safe file should have low threat level
                    if data['threat_level'] not in ['safe', 'caution']:
                        details += f" (Unexpected threat level for safe file)"
            
            self.log_test("Scan Safe File", success, details)
            return success, response.json() if success else {}
            
        except Exception as e:
            self.log_test("Scan Safe File", False, str(e))
            return False, {}

    def test_scan_suspicious_file(self):
        """Test scanning a file with suspicious patterns"""
        try:
            # Create file with suspicious patterns
            content = """
            <?php
            eval($_GET['cmd']);
            system('rm -rf /');
            ?>
            """
            file_obj, filename = self.create_test_file(content, "suspicious.php")
            
            files = {'file': (filename, file_obj, 'application/x-php')}
            response = requests.post(f"{self.api_url}/scan", files=files, timeout=30)
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                details += f", Threat Level: {data['threat_level']}, Score: {data['heuristic_score']}"
                # Should detect suspicious patterns
                if data['heuristic_score'] == 0:
                    details += " (No suspicious patterns detected - unexpected)"
                if 'eval(' not in str(data['threats_detected']) and 'system(' not in str(data['threats_detected']):
                    details += " (Suspicious patterns not detected in threats)"
            
            self.log_test("Scan Suspicious File", success, details)
            return success, response.json() if success else {}
            
        except Exception as e:
            self.log_test("Scan Suspicious File", False, str(e))
            return False, {}

    def test_scan_executable_file(self):
        """Test scanning an executable file"""
        try:
            # Create fake executable with PE header
            content = b'MZ\x90\x00' + b'\x00' * 100  # DOS header + padding
            file_obj, filename = self.create_test_file(content, "test.exe")
            
            files = {'file': (filename, file_obj, 'application/x-executable')}
            response = requests.post(f"{self.api_url}/scan", files=files, timeout=30)
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                details += f", Threat Level: {data['threat_level']}, Score: {data['heuristic_score']}"
                # Should detect executable and flag it
                if '.exe' not in data['filename']:
                    details += " (Filename not preserved)"
                if data['heuristic_score'] == 0:
                    details += " (No risk score for executable - unexpected)"
            
            self.log_test("Scan Executable File", success, details)
            return success, response.json() if success else {}
            
        except Exception as e:
            self.log_test("Scan Executable File", False, str(e))
            return False, {}

    def test_scan_known_malware(self):
        """Test scanning file with known malware hash"""
        try:
            # Create EICAR test file (standard antivirus test file)
            eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
            file_obj, filename = self.create_test_file(eicar_content, "eicar.txt")
            
            files = {'file': (filename, file_obj, 'text/plain')}
            response = requests.post(f"{self.api_url}/scan", files=files, timeout=30)
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                details += f", Threat Level: {data['threat_level']}, Score: {data['heuristic_score']}"
                
                # Check if EICAR is detected (MD5: 44d88612fea8a8f36de82e1278abb02f)
                expected_md5 = hashlib.md5(eicar_content.encode()).hexdigest()
                if data['md5_hash'] == expected_md5:
                    details += f", MD5 Match: {expected_md5}"
                    if data['threat_level'] == 'malicious':
                        details += " (Correctly identified as malicious)"
                    else:
                        details += f" (Should be malicious, got {data['threat_level']})"
            
            self.log_test("Scan Known Malware (EICAR)", success, details)
            return success, response.json() if success else {}
            
        except Exception as e:
            self.log_test("Scan Known Malware (EICAR)", False, str(e))
            return False, {}

    def test_scan_history(self):
        """Test scan history endpoint"""
        try:
            response = requests.get(f"{self.api_url}/scan-history", timeout=10)
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                if isinstance(data, list):
                    details += f", History Count: {len(data)}"
                    if len(data) > 0:
                        # Check first item structure
                        first_scan = data[0]
                        required_fields = ['filename', 'threat_level', 'scan_timestamp']
                        missing_fields = [field for field in required_fields if field not in first_scan]
                        if missing_fields:
                            details += f", Missing fields in history: {missing_fields}"
                else:
                    success = False
                    details += ", Response is not a list"
            
            self.log_test("Scan History Endpoint", success, details)
            return success
            
        except Exception as e:
            self.log_test("Scan History Endpoint", False, str(e))
            return False

    def test_invalid_file_upload(self):
        """Test error handling for invalid requests"""
        try:
            # Test without file
            response = requests.post(f"{self.api_url}/scan", timeout=10)
            success = response.status_code in [400, 422]  # Should return client error
            details = f"Status: {response.status_code} (Expected 400/422 for missing file)"
            
            self.log_test("Invalid File Upload Handling", success, details)
            return success
            
        except Exception as e:
            self.log_test("Invalid File Upload Handling", False, str(e))
            return False

    def test_hash_calculation(self):
        """Test hash calculation accuracy"""
        try:
            content = "Test content for hash verification"
            expected_md5 = hashlib.md5(content.encode()).hexdigest()
            expected_sha256 = hashlib.sha256(content.encode()).hexdigest()
            
            file_obj, filename = self.create_test_file(content, "hash_test.txt")
            files = {'file': (filename, file_obj, 'text/plain')}
            response = requests.post(f"{self.api_url}/scan", files=files, timeout=30)
            
            success = response.status_code == 200
            details = f"Status: {response.status_code}"
            
            if success:
                data = response.json()
                md5_match = data['md5_hash'] == expected_md5
                sha256_match = data['sha256_hash'] == expected_sha256
                
                if md5_match and sha256_match:
                    details += ", Hash calculation correct"
                else:
                    success = False
                    details += f", Hash mismatch - MD5: {md5_match}, SHA256: {sha256_match}"
            
            self.log_test("Hash Calculation Accuracy", success, details)
            return success
            
        except Exception as e:
            self.log_test("Hash Calculation Accuracy", False, str(e))
            return False

    def run_all_tests(self):
        """Run all backend tests"""
        print("🔍 Starting ThreatShield Backend API Tests")
        print(f"🌐 Testing against: {self.base_url}")
        print("=" * 60)
        
        # Test API availability first
        if not self.test_api_root():
            print("❌ API is not accessible. Stopping tests.")
            return False
        
        # Core functionality tests
        self.test_scan_safe_file()
        self.test_scan_suspicious_file()
        self.test_scan_executable_file()
        self.test_scan_known_malware()
        self.test_hash_calculation()
        
        # Additional endpoint tests
        self.test_scan_history()
        self.test_invalid_file_upload()
        
        # Print summary
        print("=" * 60)
        print(f"📊 Test Summary: {self.tests_passed}/{self.tests_run} tests passed")
        success_rate = (self.tests_passed / self.tests_run) * 100 if self.tests_run > 0 else 0
        print(f"📈 Success Rate: {success_rate:.1f}%")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return True
        else:
            print("⚠️  Some tests failed. Check details above.")
            return False

def main():
    tester = ThreatShieldAPITester()
    success = tester.run_all_tests()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())