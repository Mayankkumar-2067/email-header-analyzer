# email-header-analyzer
A powerful Python-based tool that analyzes raw email headers to detect spoofing, phishing indicators, and mail flow issues. Perfect for SOC analysts and blue team investigations.
# Email Header Analyzer

📧 This tool parses and analyzes email headers to detect:
- SPF/DKIM/DMARC issues
- Spoofed sender addresses
- Suspicious received paths
- Mismatched Return-Path

✅ Useful for SOC analysts, Blue Teamers, and phishing analysts.

## 🔧 Usage

1. Save email headers in a `.txt` file (copy raw headers from email client)
2. Run:
   ```bash
   python3 email_header_analyzer.py
   JSON output will be saved with detected issues.



📌 Output Sample

{
  "From": "\"Amazon Support\" <support@amaz0n.com>",
  "Return-Path": "phisher@fakesite.com",
  "SPF": "fail (domain of fakesite.com does not designate 192.168.1.100)",
  "DKIM": "fail",
  "DMARC": "fail",
  "Flags": [
    "⚠️ Return-Path mismatch - possible spoofing",
    "❌ SPF failed",
    "❌ DKIM failed",
    "❌ DMARC failed"
  ]
}
Installation ➡️ https://github.com/Mayankkumar-2067/email-header-analyzer.git
