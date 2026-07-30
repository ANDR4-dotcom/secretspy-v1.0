# 🕵️ SecretSpy

**SecretSpy** is a command-line security tool that automatically detects exposed API keys, tokens, and secrets on websites.

## ✨ Features

- 🔍 **Web Crawling** - Automatically explores websites
- 🔑 **Secret Detection** - Finds 25+ types of API keys
- 📊 **JSON Reports** - Saves findings in structured format
- 🎨 **Color Output** - Easy-to-read terminal display
- 📁 **Source Map Scanning** - Finds hidden secrets

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/secretspy.git
cd secretspy

# Install dependencies
pip install -r requirements.txt

---> Usage

# Basic scan
python secretspy.py https://example.com

# Scan with page limit
python secretspy.py https://example.com --max-pages 30

# Save report
python secretspy.py https://example.com --output report.json

----> Example Output

🔍 SCANNING: https://example.com
📄 [1/15] Scanning: https://example.com...
   ⚠️  Found 2 secrets!
      → 🔑 Google Maps API Key: AIzaSy...
      → 📁 Source Map Found: map.js.map

📊 SECRETSPY SCAN RESULTS
============================================================
⏱️  Scan Duration: 12.3 seconds
📄 Pages Scanned: 8
🔑 Secrets Found: 6

--->🔐 Supported Secrets
 --------------------------------------------------------
   Service          Pattern                     Severity
 --------------------------------------------------------
 Google Api        AIza[0-9A-Za-z\-_]{35}         HIGH
 --------------------------------------------------------
 AWS Access Key    AKIA[0-9A-Z]{16}             CRITICAL
 --------------------------------------------------------
 GitHub Token      gh[pousr]_[A-Za-z0-9]{36,}   CRITICAL
 --------------------------------------------------------
 Stripe Secret     sk_live_[A-Za-z0-9]{24,}     CRITICAL
 --------------------------------------------------------
 JWT Token         eyJ[A-Za-z0-9_-]{5,}\.        
                   [A-Za-z0-9_-]{5,}\.           HIGH
                   [A-Za-z0-9_-]{5,}  
 --------------------------------------------------------
 Slack Token       xox[baprs]-[A-Za-z0-9-]{10,}  HIGH
 --------------------------------------------------------
 MongoDB URI       mongodb(\+srv)?://[A-Za-z0-9. CRITICAL
                   _%-]+:[^@\s]+@[^\s'"]+
 --------------------------------------------------------
 And 18+ more patterns
 
 🛠️ Technology Stack
  . Python 3 - Core language
  . Requests - HTTP client
  . BeautifulSoup4 - HTML parsing
  . Regex - Pattern matching

 📝 Command Line Options
  
 Option          Description                  Default
 ----------------------------------------------------
 --max-pages    Maximum pages to scan           15
 ----------------------------------------------------
 --output       Output file for Json report    None
 ----------------------------------------------------
 --delay        Delay between requests         0.3s
 ----------------------------------------------------

 ⚠️ Disclaimer
 
 IMPORTANT: Only use this tool on website you own or have explicit permission to 
 test. Unauthorized scanning may violate terms of service and laws.

 🤝 Contributing
 
 Contributions are welcome! Feels free to:
 
 . Add new secret patterns

 . Improve the crawler

 . Fix bugs 
 
 . Suggest features 

 📄 License
  
 MIT License - see LICENSE file for details.

 👨‍💻 Author
 
 Pranav ps 
 
 . GitHub: ANDR4-dotcom
 . Linkedin:https://www.linkedin.com/in/pranav-ps-3585132a1?utm_source=share_
                  via&utm_content=profile&utm_medium=member_android
 ⭐ Star History
  
 if you find this useful, please give it a star! ⭐

