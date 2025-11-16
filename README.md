<img width="1337" height="769" alt="cisa-kev-analyzer-screenshot" src="https://github.com/user-attachments/assets/4e4c3176-9e8f-471a-b3ff-45ccd53a4085" />

# CISA KEV Analyzer 🛡️

This tool is a Python command-line script to query, analyze, and enrich the CISA [**Known Exploited Vulnerabilities (KEV)**](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog.

Originally a simple technical challenge for an internship interview, this project was expanded into a complete piece, demonstrating API management, caching, data enrichment (via NVD), and structured output.

-----

## 🚀 Features

  * **KEV Querying**: Fetches the most recent list of actively exploited vulnerabilities.
  * **Smart Caching**: Uses a local cache for both KEV and CVSS data to minimize API calls and speed up executions.
  * **CVSS Enrichment**: Queries the NIST NVD 2.0 API to retrieve the **CVSS score** and **severity level** for found vulnerabilities.
  * **Advanced Filtering**: Filter results by:
      * Number of days (`-d`)
      * Number of results (`-n`)
      * Vendor (`-s` or `--search-vendor`)
  * **Vendor Statistics**: Displays a Top `N` list of the most frequent vendors in the KEV catalog.
  * **Multiple Output Formats**: Display results in the `console` or export them as `json` or `csv` to integrate with other tools.

-----

## 🛠️ Installation and Configuration

### 1\. Prerequisites

  * Python 3.7+
  * Git

### 2\. Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/antoineburet/cisa-kev-analyzer.git
    cd cisa-kev-analyzer
    ```

2.  (Recommended) Create a virtual environment:

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: .\venv\Scripts\activate
    ```

3.  Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

### 3\. Configuration (Important\!)

CVSS enrichment (`--enrich`) queries the NVD API, which enforces **rate limits**.

  * **Without an API key**: You will be limited to \~5 requests per 30 seconds. Enrichment will be **very slow**.
  * **With a (Free) API key**: You can make \~50 requests per 30 seconds.

**It is highly recommended to get an NVD API key:**

1.  Go to the [NVD API page](https://nvd.nist.gov/developers/request-an-api-key) and request a key.

2.  Export your key as an environment variable.

      * **On macOS/Linux:**
        ```bash
        export NVD_API_KEY="YOUR_NVD_API_KEY_HERE"
        ```
      * **On Windows (PowerShell):**
        ```powershell
        $Env:NVD_API_KEY = "YOUR_NVD_API_KEY_HERE"
        ```

The `kev_analyzer.py` script will automatically detect and use this key.

-----

## 📖 Usage Examples

➡️ **Show the help menu**

```bash
python3 kev_analyzer.py -h
```

➡️ **Basic usage**
*(Shows the last 5 vulnerabilities from the last 30 days and the Top 10 vendors)*

```bash
python3 kev_analyzer.py
```

➡️ **CVSS Enrichment**
*(Shows the last 2 vulnerabilities from the last 60 days, WITH their CVSS score)*

```bash
python3 kev_analyzer.py -n 2 -d 60 --enrich
```

*Expected output:*

```bash
[INFO] Enriching CVSS for 2 vulnerability(s). (This may take time...)
[INFO] [1/2] Processing CVE-202X-XXXXX...
[INFO] Enriching CVSS for CVE-202X-XXXXX (NVD API Call...)
[INFO] [2/2] Processing CVE-202X-YYYYY...

--- 1. Vulnerability Analysis (Total: 2) ---

  CVE ID:         CVE-202X-XXXXX
  CVSS Score:     9.8 (CRITICAL)
  Vendor/Product: Microsoft / Windows
  Date Added:     2025-11-14

  CVE ID:         CVE-202X-YYYYY
  CVSS Score:     7.5 (HIGH)
  Vendor/Product: Apple / iOS
  Date Added:     2025-11-12
...
```

➡️ **Search by vendor and export to JSON**
*(Finds the last 10 "Microsoft" vulnerabilities from the last 180 days and saves everything to JSON)*

```bash
python3 kev_analyzer.py -n 10 -d 180 -s "Microsoft" -f json -o microsoft_report.json
```

➡️ **Export all "Fortinet" vulnerabilities to CSV**
*(The `-n 9999` is used to retrieve "all" entries)*

```bash
python3 kev_analyzer.py -n 9999 -d 3650 -s "Fortinet" -f csv -o fortinet.csv
```

➡️ **Force refresh the caches**

```bash
python3 kev_analyzer.py --force-refresh
```
