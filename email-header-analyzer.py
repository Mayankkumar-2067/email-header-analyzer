import re
import json
from datetime import datetime

def parse_email_headers(headers: str) -> dict:
    result = {}

    # 1. From
    from_match = re.search(r"From:\s?(.*)", headers)
    result['From'] = from_match.group(1).strip() if from_match else "Not found"

    # 2. Return-Path
    return_path = re.search(r"Return-Path:\s?<(.*)>", headers)
    result['Return-Path'] = return_path.group(1).strip() if return_path else "Not found"

    # 3. SPF
    spf_result = re.search(r"Received-SPF:\s?(.*)", headers)
    result['SPF'] = spf_result.group(1).strip() if spf_result else "Not found"

    # 4. DKIM
    dkim_result = re.search(r"Authentication-Results:.*?dkim=(\w+)", headers)
    result['DKIM'] = dkim_result.group(1) if dkim_result else "Not found"

    # 5. DMARC
    dmarc_result = re.search(r"Authentication-Results:.*?dmarc=(\w+)", headers)
    result['DMARC'] = dmarc_result.group(1) if dmarc_result else "Not found"

    # 6. Message ID
    msg_id = re.search(r"Message-ID:\s?<(.*)>", headers)
    result['Message-ID'] = msg_id.group(1).strip() if msg_id else "Not found"

    # 7. Date
    date_match = re.search(r"Date:\s?(.*)", headers)
    result['Date'] = date_match.group(1).strip() if date_match else "Not found"

    # 8. Received Paths
    received = re.findall(r"Received: from (.*)", headers)
    result['Received-path'] = received if received else ["Not found"]

    # 9. User-Agent or X-Mailer
    ua = re.search(r"(User-Agent|X-Mailer):\s?(.*)", headers)
    result['Mailer'] = ua.group(2).strip() if ua else "Not found"

    # 10. Flags
    result['Flags'] = []
    if result['From'] != result['Return-Path'] and result['Return-Path'] != "Not found":
        result['Flags'].append("⚠️ Return-Path mismatch - possible spoofing")
    if result['SPF'].lower().startswith("fail"):
        result['Flags'].append("❌ SPF failed")
    if result['DKIM'] == "fail":
        result['Flags'].append("❌ DKIM failed")
    if result['DMARC'] == "fail":
        result['Flags'].append("❌ DMARC failed")

    return result


def main():
    print("=== Email Header Analyzer ===")
    file = input("Enter header file path (e.g. sample_headers.txt): ").strip()

    try:
        with open(file, 'r', encoding='utf-8') as f:
            raw_headers = f.read()

        analysis = parse_email_headers(raw_headers)

        # Output JSON
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"email_analysis_{ts}.json"
        with open(output_file, 'w') as out:
            json.dump(analysis, out, indent=4)

        print("\n✅ Analysis complete!")
        print(f"Saved to: {output_file}")
        print("\nFlags:")
        for flag in analysis.get("Flags", []):
            print("  ", flag)

    except FileNotFoundError:
        print("❌ File not found. Please check the path.")
    except Exception as e:
        print("❌ Error:", e)


if __name__ == "__main__":
    main()
