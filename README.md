# AEPL Autonomous SAP Invoice Parking Engine

> Enterprise-grade Accounts Payable automation engine powered by Google Gemini 3.8 Flash, Google Cloud Model Armor, and SAP S/4HANA BAPI integration.

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/AuroGroupAutomationBot/aepl-invoice-automation/actions)
[![Cloud Run](https://img.shields.io/badge/Google%20Cloud%20Run-us--central1-blue.svg)](https://cloud.google.com/run)
[![Model](https://img.shields.io/badge/Vertex%20AI-Gemini%203.8%20Flash-blueviolet.svg)](https://cloud.google.com/vertex-ai)
[![Security](https://img.shields.io/badge/Security-Model%20Armor-success.svg)](https://cloud.google.com/security)
[![SAP](https://img.shields.io/badge/SAP%20S%2F4HANA-MIR7%20BAPI-0070f2.svg)](https://www.sap.com)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)]()

---

## Overview

In traditional corporate finance operations, Accounts Payable (AP) specialists spend thousands of hours manually entering vendor tax invoices into SAP S/4HANA using transactions such as `MIR7` (Park Incoming Invoice) and `MIRO` (Enter Incoming Invoice). This manual process introduces severe data entry bottlenecks, high operational costs, duplicate payment liabilities, and vulnerabilities to invoice fraud and prompt injection attacks embedded in digital invoice documents.

The **AEPL Autonomous SAP Invoice Parking Engine** solves this problem by delivering a zero-trust, event-driven serverless platform. Built on Google Cloud Run and Vertex AI, the engine ingests unstructured invoices (multi-page PDFs, scans, and mobile captures), extracts header and line-item data using **Gemini 3.8 Flash**, sanitizes the model output against prompt injection and malicious URIs via **Google Cloud Model Armor**, enforces strict SAP ABAP DDIC data types, and submits a balanced document directly to SAP S/4HANA via SAP Cloud Platform Integration (CPI) with automated attachment archiving in DmacQ DMS.

---

## What It Is Used For

* **Autonomous SAP MIR7 Invoice Parking**: Eliminates manual accounting data entry by extracting vendor invoice numbers, purchasing document numbers, line items, unit rates, quantities, and statutory taxes directly into SAP BAPI format.
* **Pre-BAPI 3-Way Match & Saldo Balance Verification**: Validates arithmetic balance ($\text{Gross Amount} = \text{Taxable Base} + \text{Tax Amount}$) with a real-time $\text{Saldo} = 0.00\text{ INR}$ verification indicator before downstream submission.
* **Adversarial Security Screening**: Protects enterprise ERP backends by screening uploaded invoices against multimodal prompt injection, hidden adversarial instructions, and untrusted URLs before executing BAPI calls.
* **DMS Document Archiving**: Merges multi-page invoice scans and Service Entry Sheets (SES) into a compressed PDF and injects the Base64 stream into SAP CPI for long-term archiving in DmacQ DMS.
* **Cross-Device Enterprise AP Portal**: Provides finance and procurement officers with an accessible, mobile-responsive SAP Fiori Horizon web portal to upload, monitor, and park invoices from any desktop, tablet, or phone.

---

## Architecture / How It Works

### High-Level System Architecture

```mermaid
flowchart TD
    subgraph Clients["Clients & Edge"]
        UserBrowser["SAP End User / AP Accountant (Desktop / Tablet / Mobile)"]
    end

    subgraph GCP["Google Cloud Platform (prj-aepl-ai-inv-auto-dev)"]
        subgraph CloudRun["Cloud Run (us-central1)"]
            FastAPI["FastAPI AP Service (sap-invoice-engine)"]
            FinOpsEngine["768px FinOps Image Scaler & PyMuPDF Engine"]
            ABAPTyper["SAP ABAP DDIC Formatter & Regex Guardrail"]
        end

        subgraph VertexAI["Vertex AI (Global Endpoint)"]
            GeminiModel["Gemini 3.8 Flash (Multimodal Structured Outputs)"]
        end

        subgraph SecuritySuite["Security & Governance"]
            FirebaseAuth["Firebase Authentication (Corporate Domain Gate)"]
            ModelArmor["Google Cloud Model Armor (us-central1: tpl-aepl-inv-armor)"]
            SecretManager["Secret Manager (SAP CPI Credentials)"]
        end
    end

    subgraph EnterpriseBackends["Enterprise Core Systems"]
        SAPCPI["SAP Cloud Platform Integration (OAuth2 / CSRF)"]
        SAPS4HANA["SAP S/4HANA ERP (BAPI_INCOMINGINVOICE_PARK / MIR7)"]
        DmacQDMS["DmacQ DMS (Invoice PDF Document Archival)"]
    end

    UserBrowser -->|"1. HTTPS / Magic Link Auth"| FirebaseAuth
    FirebaseAuth -->|"2. Verify Token & Domain"| FastAPI
    UserBrowser -->|"3. Multipart Upload (PDF / Scans)"| FastAPI
    FastAPI -->|"4. 768px Tile Constraint"| FinOpsEngine
    FinOpsEngine -->|"5. Multimodal Inference"| GeminiModel
    GeminiModel -->|"6. Structured JSON Response"| FastAPI
    FastAPI -->|"7. Sanitize Response"| ModelArmor
    ModelArmor -->|"8. Policy Cleared (No Threat Match)"| ABAPTyper
    FastAPI -.->|"Fetch Credentials"| SecretManager
    ABAPTyper -->|"9. BAPI Payload with Base64 PDF"| SAPCPI
    SAPCPI -->|"10. Execute MIR7 BAPI"| SAPS4HANA
    SAPCPI -->|"11. Store Base64 Document"| DmacQDMS
    SAPCPI -->|"12. Return BELNR Document Confirmation"| FastAPI
    FastAPI -->|"13. Real-Time Status & Saldo 0.00"| UserBrowser
```

### Detailed Request / Response Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor AP as AP Accountant
    participant UI as SAP Fiori Portal (Browser)
    participant API as Cloud Run (sap-invoice-engine)
    participant AI as Vertex AI (Gemini 3.8 Flash)
    participant MA as Model Armor (tpl-aepl-inv-armor)
    participant CPI as SAP CPI Middleware
    participant SAP as SAP S/4HANA ERP

    AP->>UI: Upload Invoice & Supporting PO / SES
    UI->>API: POST /api/park-invoice (Multipart + Firebase JWT)
    API->>API: Validate Corporate Email (@axisclinicals.com / @aurogroup.com)
    API->>API: Process in RAM: Merge to PDF + 768px FinOps Image Optimization
    API->>AI: generate_content(Model: gemini-3.8-flash, Schema: ExtractionInvoiceSchema)
    AI-->>API: Extracted JSON (HeaderData + ItemData)
    API->>MA: SanitizeModelResponseRequest(Template: tpl-aepl-inv-armor)
    MA-->>API: FilterMatchState: NO_MATCH (Clean)
    API->>API: Inject Base64 PDF into HeaderData.Attachment
    API->>API: Validate Schema Guardrails (PO: 10-digit, SES: 1-series, Taxable > 0)
    API->>CPI: POST /OAuth/Token (Client Credentials)
    CPI-->>API: Access Token
    API->>CPI: GET /cpi_uri (x-csrf-token: fetch)
    CPI-->>API: CSRF Token
    API->>CPI: POST Request_VendorInvoice_Park_AEPL (ZMM_VENDORINV_PARK_AUTOMATE)
    CPI->>SAP: BAPI_INCOMINGINVOICE_PARK
    SAP-->>CPI: Response_VendorInvoice_Park_AEPL (Status: 'S', BELNR: '5105600001')
    CPI-->>API: 200 OK + SAP Confirmation Message
    API-->>UI: 200 OK (Status: SUCCESS, BELNR: 5105600001, TraceID, Telemetry)
    UI-->>AP: Display Parked Card, Saldo: 0.00 INR, and BELNR Copy Button
```

### Canonical SAP Invoice Data Model

```mermaid
erDiagram
    HEADER_DATA ||--|{ ITEM_DATA : contains

    HEADER_DATA {
        string RefDocNo "Vendor Tax Invoice Number (XBLNR)"
        string DocDate "Invoice Date in DD.MM.YYYY format (BLDAT)"
        string PONumber "10-digit SAP Purchase Order Number (EBELN)"
        string SES "10-digit Service Entry Sheet starting with 1 (LBLNI)"
        string CompName "Legal entity receiving the invoice (Billed To)"
        string CompCode "SAP Company Code (e.g. 8000, 9000, 1000)"
        string BusinessPlace "SAP Business Place Code (e.g. 2701, 2702, 3701, 3601)"
        float TaxableVal "Net taxable base value before GST"
        float TotalInvVal "Final gross amount inclusive of all taxes"
        string Attachment "Base64 encoded merged PDF stream"
    }

    ITEM_DATA {
        int SlNo "Sequential item line index"
        string ItemText "Material description / goods text (<= 50 chars)"
        float ItemQuantity "Invoiced quantity (MENGE)"
        float ItemRate "Unit price before taxes (NETPR)"
        float ItemAmount "Net taxable line total (WRBTR)"
    }
```

---

## Key Features

* **Strict Alignment with AEPL Reference Notebook**: Exact parity with schemas, field conventions (`HeaderData`, `ItemData`), system instructions, and pre-CPI validation rules from `AEPL_Invoice_Parking_Automation_Using_Google_ADK.ipynb`.
* **Multimodal Extraction via Gemini 3.8 Flash**: Employs Vertex AI's `gemini-3.8-flash` model via the `global` publisher endpoint with structured outputs (`response_schema`), delivering low-latency parsing across multi-page tables and split scans.
* **Quota-Aware Resilient Exponential Backoff**: Automatic retry mechanism handling Vertex AI 429 (Resource Exhausted) and 503 (Unavailable) transient spikes with jittered backoff, directly mirroring the notebook's resilience patterns.
* **Egress Firewall Security Screening**: Pre-BAPI inspection by regional **Google Cloud Model Armor** (`tpl-aepl-inv-armor` in `us-central1`) screens the extracted JSON for indirect prompt injection, malicious URLs, and adversarial payloads before ERP execution.
* **10 MB Enterprise Document Payload Limit**: Enforces a strict 10 MB maximum document size limit per business specification. Accommodates single and multi-page PDFs and images while protecting against payload exhaustion.
* **The 768px FinOps Rule**: Image inputs (PNG/JPG) are automatically scaled to $768\times 768$ pixels before inference, constraining visual token consumption to exactly 258 tokens per page ($75\%$ cost reduction compared to unscaled uploads).
* **Deterministic SAP ABAP DDIC Type Enforcement**: Automatic casting of numeric amounts to 2 decimal places, date normalization to `DD.MM.YYYY`, and string length bounding prevents downstream BAPI dumps.
* **10-Digit SAP PO & SES Regex Guardrails**: Hard firewall validating that `PONumber` is strictly a 10-digit integer (`^\d{10}$`) and `SES` is a 10-digit number starting with 1 (`^1\d{9}$`).
* **In-Memory Universal PDF & DMS Attachment Pipeline**: Multi-page scans and PDFs are merged, compressed, and converted to Base64 in RAM via PyMuPDF/Pillow and injected into `HeaderData.Attachment` for DmacQ DMS archival without disk overhead.
* **Direct VPC Egress with Private Google Access**: Attached to VPC `vpc-aepl-inv-sec` and subnet `sub-aepl-us` (`10.20.1.0/24`) with `private-ranges-only`, keeping private SAP ERP communication isolated while communicating with Google APIs via Google's internal private backbone.
* **Central Cloud Firestore Store (Mumbai `asia-south1`)**: Native persistence for invoice lifecycle (`invoices`), audit trail (`audit_logs`), auth events (`auth_events`), and failure incidents (`incident_alerts`) with sanitized attachment protection (< 1 MiB doc limit).
* **Self-Service Human-in-the-Loop (HITL) with Comprehensive Value Visibility**:
  * **Full Invoice Attribute & Line Item Parity**: The HITL interface displays all extracted values identically to the SAP parked success view—including the full 8-attribute header grid (`RefDocNo`, `DocDate`, `CompCode`, `CompName`, `Gross Value`, `Taxable Base`, `Business Place`, `Service Entry Sheet (SES)`) and the complete multi-row Line Items table (`ItemData`), removing artificial tax estimates that confuse end-users.
  * **Strict Field Immutability (Read-Only Guardrails 🔒)**: All extracted invoice header attributes and line items are locked and strictly read-only to prevent tampering with financial figures or vendor data.
  * **Isolated PO & SES Editable Fields**: Only the Purchase Order (`PONumber`, mandatory 10-digit `^\d{10}$`) and Service Entry Sheet (`SES`, optional 10-digit `^1\d{9}$`) fields are editable.
  * **SAP Rejection Finality (Status 'E')**: When SAP CPI rejects a document (response status `'E'`), the rejection is final. The **'Validate & Resume Parking in SAP'** button is permanently disabled in the UI, accompanied by an explicit rejection advisory banner, and the backend `/api/invoices/{trace_id}/resolve-hitl` API strictly rejects resume attempts with HTTP 400.
* **SAP CPI XML/JSON Dual-Format BAPI Parsing (`Response_VendorInvoice_Park_AEPL`)**:
  * **Native XML Schema Compliance**: Fully compliant with the official SAP CPI response schema (`<root><Response_VendorInvoice_Park_AEPL>...</Response_VendorInvoice_Park_AEPL></root>`).
  * **Comprehensive 11-Attribute Extraction**: Accurately extracts `Status`, `Message`, `DocNum` (Accounting Document / BELNR), `Year` (Fiscal Year), `RefDocNo`, `PONumber`, `SES`, `GRN`, `CompName`, `CompCode`, and `BusinessPlace`.
  * **Elimination of Fragile Regex Extraction**: `belnr` is mapped directly from `<DocNum>` rather than parsing message strings, with automatic fallback for older mock payloads.
* **Keyless CI/CD with Workload Identity Federation (WIF v2)**: GitHub Actions authenticates to Google Cloud via short-lived OIDC federated tokens (`wif-aepl-github-pool-v2`), completely eliminating static service account JSON keys.
* **Universal Cross-Device SAP Fiori Horizon Portal**: Fully responsive web application compatible with desktops, tablets, and smartphones, incorporating touch targets ($\ge 44\text{px}$), iOS zoom-prevention, horizontal momentum scrolling, and zero prototype clutter.
* **Stage-Aware Live Processing Beacon & Shimmer Progress**:
  * **Eliminated Stopwatch/Seconds Display**: Replaced ticking digital elapsed timers (e.g. `27.0s`) with an animated glowing pulse beacon and stage-aware live status badges (`● Ingesting`, `● Multimodal AI Extraction`, `● Security Screening`, `● Posting to SAP S/4HANA`), removing perceived wait time and user anxiety.
  * **Smooth Shimmer Progress Bar**: Features a subtle 3px gradient shimmer progress indicator that advances across the 4 execution stages (25% $\to$ 50% $\to$ 75% $\to$ 90% $\to$ 100%), culminating in clear terminal status pills (`✓ Parked in SAP`, `⚠ Action Required`, `⚠ SAP Rejected`).
* **Corporate Single Sign-On Gating**: Passwordless email link authentication restricted exclusively to authorized enterprise domains (`@axisclinicals.com`, `@aurogroup.com`, `@ent.aurogroup.com`).
* **Strict Password Reset Workflow Isolation (NIST SP 800-63B & OWASP ASVS 2.3)**:
  * **Zero Auto-Login on Reset Links**: Accessing password reset links (`?action=reset-password&token=...`) strictly isolates the workflow—purging existing cached sessions in `localStorage` and Firebase Auth to guarantee zero unauthorized auto-login or account takeover.
  * **Mandatory Explicit Password Entry**: Reviewers and administrators must actively key in their desired new password with live NIST SP 800-63B complexity validation (length $\ge 8$, uppercase, lowercase, digit, special character).
  * **Cryptographic Token Consumption & Re-Authentication**: Single-use tokens expire in 15 minutes and are consumed immediately upon reset. Upon completion, the user is transitioned to the sign-in screen to authenticate with their new credentials.

---

## Getting Started

### Prerequisites

* **Google Cloud SDK (`gcloud`)** installed and authenticated:
  ```bash
  gcloud auth login
  gcloud config set project prj-aepl-ai-inv-auto-dev
  ```
* **Python 3.11+** installed locally.
* **Docker** installed (optional, for local container emulation).

### Local Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/AuroGroupAutomationBot/aepl-invoice-automation.git
   cd aepl-invoice-automation
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: .\venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Run the local development server**:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8080 --reload
   ```

5. **Verify health endpoint**:
   ```bash
   curl http://localhost:8080/healthz
   ```

### Minimal Working Example: Parking an Invoice

Submit an invoice directly via `curl`:

```bash
curl -X POST "https://sap-invoice-engine-411369932113.us-central1.run.app/api/park-invoice" \
  -H "Authorization: Bearer <FIREBASE_ID_TOKEN>" \
  -F "files=@sample_invoice.pdf"
```

Expected JSON Response:
```json
{
  "status": "SUCCESS",
  "trace_id": "a1b2c3d4",
  "sap_message": "Document [5105600001] parked successfully in SAP S/4HANA (Company Code 1000, Fiscal Year 2026).",
  "extracted_data": {
    "HeaderData": {
      "RefDocNo": "INV-2026-0891",
      "DocDate": "26.10.2026",
      "PONumber": "4500123456",
      "SES": "1000456789",
      "CompName": "Auro Enterprises Private Limited",
      "CompCode": "8000",
      "BusinessPlace": "2701",
      "TaxableVal": 125000.00,
      "TotalInvVal": 147500.00
    },
    "ItemData": [
      {
        "SlNo": 1,
        "ItemText": "Industrial Solvent Drums Grade A",
        "ItemQuantity": 50.0,
        "ItemRate": 2500.0,
        "ItemAmount": 125000.0
      }
    ]
  },
  "telemetry": {
    "cpi_time": 0.842,
    "sap_time": 0.418,
    "pdf_size_mb": 0.185,
    "total_exec_time": 3.21,
    "submitted_by": "finance-operations@aurogroup.com",
    "model": "gemini-3.8-flash"
  }
}
```

---

## Configuration

### Environment Variables

| Variable | Type | Default Value | Description |
| :--- | :--- | :--- | :--- |
| `GCP_PROJECT` | String | `prj-aepl-ai-inv-auto-dev` | Target Google Cloud Project ID. |
| `GCP_LOCATION` | String | `us-central1` | Default regional deployment zone. |
| `RUN_REGION` | String | `us-central1` | Cloud Run service execution region. |
| `VERTEX_LOCATION` | String | `global` | Regional/global endpoint for Vertex AI Gemini 3.8 Flash. |
| `GEMINI_MODEL` | String | `gemini-3.8-flash` | Multimodal foundational model identifier. |
| `MODEL_ARMOR_LOCATION` | String | `us-central1` | Regional location hosting Model Armor templates. |
| `MODEL_ARMOR_TEMPLATE` | String | `tpl-aepl-inv-armor` | Template resource ID for adversarial screening. |
| `FIRESTORE_LOCATION` | String | `asia-south1` | Centralized Cloud Firestore location (Mumbai, India). |
| `MAX_FILE_SIZE_BYTES` | Integer | `10485760` | Maximum document upload size limit (10 MB strict enterprise limit). |
| `ADMIN_EMAILS` | String | `aic1176@aurogroup.com` | Designated System Administrator email(s) for MIS privileges. |
| `ALERT_EMAIL_RECIPIENT` | String | `aic1176@aurogroup.com` | Recipient for automated failure model alerts and notifications. |
| `ALERT_SENDER_EMAIL` | String | `aic1176@aurogroup.com` | From address for outgoing failure alert emails (must be a mailbox you own or have verified with your email provider). |
| `MAIL_COLLECTION` | String | `mail` | Firestore collection path monitored by the `firestore-send-email` extension. |
| `ALERT_WEBHOOK_URL` | String | *(Optional)* | HTTPS Webhook URL (e.g. Microsoft Power Automate HTTP trigger) for corporate alerts without SMTP. |
| `ALLOWED_EMAIL_DOMAINS` | String | `ent.aurogroup.com;aurogroup.com;axisclinicals.com` | Semicolon-delimited authorized corporate domains. |
| `ALLOWED_EMAILS` | String | *(Whitelisted corporate users)* | Semicolon-delimited authorized employee email addresses. |

### Automated Failure Alerts (Official Firebase Extension: `firestore-send-email`)

The application integrates natively with the official Firebase Extension: [Trigger Email from Firestore (`firestore-send-email`)](https://firebase.google.com/docs/extensions/official/firestore-send-email).

#### How It Works (Decoupled & Zero Container SMTP)

1. Whenever an invoice fails (Gemini extraction crash, Model Armor security block, SAP CPI BAPI rejection, or unhandled exception), the application backend (`main.py`) writes an email document directly to the Cloud Firestore collection `mail/{mailId}` in Mumbai (`asia-south1`).
2. The document follows the official `firestore-send-email` schema:
   ```json
   {
     "to": ["aic1176@aurogroup.com"],
     "from": "aic1176@aurogroup.com",
     "replyTo": "aic1176@aurogroup.com",
     "message": {
       "subject": "[SAP AP FAILURE ALERT] Purchase Order Missing - invoice_102.pdf (trace_a8f3)",
       "text": "Plain text summary of the failure...",
       "html": "<html>Rich HTML alert with incident table and action links</html>"
     },
     "incident_id": "inc_9b2e1f44",
     "failure_type": "ERR_MISSING_PO",
     "filename": "invoice_102.pdf",
     "trace_id": "trace_a8f3",
     "timestamp": "2026-10-27T14:00:00Z"
   }
   ```
3. The official Firebase Extension automatically picks up the new document from `mail`, sends the email to `aic1176@aurogroup.com`, and records the delivery status (`delivery.state: "SUCCESS"`) directly on the document.
4. **Cloud Run does NOT need SMTP credentials or email delivery libraries.** Cloud Run only requires standard Firestore write permissions (`roles/datastore.user`), which its attached Service Account already possesses.

---

### Recommended Alternatives to SendGrid

You can configure the `firestore-send-email` extension with any of these reliable alternatives:

| Provider | Free Allowance | Setup Difficulty | Best For | Connection URI / Config in Firebase Extension |
| :--- | :--- | :--- | :--- | :--- |
| **Brevo** *(formerly Sendinblue)* | **300 emails / day forever** | Very Easy (No credit card needed) | **Recommended for Quick Setup** | `smtps://<login>:<smtp_key>@smtp-relay.brevo.com:465` |
| **MailerSend** | **3,000 emails / month forever** | Easy | Large volume free tier | `smtps://<username>:<password>@smtp.mailersend.net:465` |
| **Google Workspace OAuth2** | Existing corporate quota | Medium (GCP Console OAuth setup) | Zero passwords, native to Google | Configure `OAuth2 Client ID`, `Client Secret`, `Refresh Token` |
| **Postmark** | **100 emails / month forever** | Easy | Exceptional inbox deliverability | `smtps://<server_token>:<server_token>@smtp.postmarkapp.com:465` |
| **Mailgun** | 3-month free trial + Flex tier | Easy | Established ESP standard | `smtps://postmaster%40<domain>:<api_key>@smtp.mailgun.org:465` |
| **AWS SES** | $0.10 per 1,000 emails | Medium (AWS IAM setup) | Lowest cost enterprise scale | `smtps://<iam_user>:<iam_pass>@email-smtp.us-east-1.amazonaws.com:465` |
| **Native Google Cloud Monitoring** | **100% Free Forever** | 1 Command | Zero 3rd-party accounts | Native GCP alert channel to `aic1176@aurogroup.com` |

---

### Step-by-Step: Installing the `firestore-send-email` Extension

#### Option A: Via Firebase Console (Recommended — 2 Minutes)
1. Open [Firebase Console Extensions](https://console.firebase.google.com/project/prj-aepl-ai-inv-auto-dev/extensions).
2. Click **Explore Extensions** and locate **Trigger Email from Firestore** (`firestore-send-email`).
3. Click **Install in project**.
4. Configure the parameters:
   - **Cloud Firestore collection:** `mail` (default)
   - **Default FROM address:** `aic1176@aurogroup.com`
   - **Default REPLY-TO address:** `aic1176@aurogroup.com`
   - **SMTP connection URI:** Paste your chosen provider's connection string (e.g., from Brevo: `smtps://your_account:your_key@smtp-relay.brevo.com:465`).
5. Click **Install Extension**. Firebase deploys the managed worker in the background.

#### Option B: Via Firebase CLI
```bash
firebase ext:install firebase/firestore-send-email \
  --project=prj-aepl-ai-inv-auto-dev \
  --local
```

#### Option C: Native Google Cloud Monitoring (Zero 3rd-Party Providers)
If your organization does not want to use any external email provider, Google Cloud can send email alerts directly to `aic1176@aurogroup.com`:
```bash
# 1. Create native Google Cloud Email Notification Channel
gcloud monitoring notification-channels create \
  --type=email \
  --display-name="AEPL Invoice Failure Alerts" \
  --channel-labels=email_address="aic1176@aurogroup.com"

# 2. Bind the channel to Cloud Run critical failure events
gcloud alpha monitoring policies create \
  --display-name="SAP Invoice Processing Failure Policy" \
  --condition-filter='resource.type="cloud_run_revision" AND jsonPayload.event="INVOICE_PROCESSING_FAILURE"' \
  --notification-channels="$(gcloud monitoring notification-channels list --filter='displayName="AEPL Invoice Failure Alerts"' --format='value(name)')" \
  --combiner="OR"
```

---

### Verifying Alert Delivery
1. Open the application portal and sign in with authorized credentials.
2. Navigate to the **Admin MIS Dashboard** tab.
3. In the **Automated Incident Failure Alerts** section, click **"Send Test Alert"**.
4. The test incident will appear in the MIS audit table and a corresponding document will be written to the `mail` collection in Firestore, triggering the configured email extension.

---

### SAP CPI Response Architecture & Firestore Collections

Every interaction with SAP CPI (`ZMM_VENDORINV_PARK_AUTOMATE`) is parsed, audited, and persisted into **Cloud Firestore (Mumbai `asia-south1`)** for financial reconciliation, compliance, and real-time dashboard visibility.

#### 1. Official SAP CPI Response Schema (`Response_VendorInvoice_Park_AEPL`)
The engine natively parses both XML and JSON responses adhering to the enterprise schema:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="root">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="Response_VendorInvoice_Park_AEPL">
          <xs:complexType>
            <xs:sequence>
              <xs:element name="Status" type="xs:string"/>
              <xs:element name="Message" type="xs:string"/>
              <xs:element name="DocNum" type="xs:string"/>
              <xs:element name="Year" type="xs:string"/>
              <xs:element name="RefDocNo" type="xs:string"/>
              <xs:element name="PONumber" type="xs:string"/>
              <xs:element name="SES" type="xs:string"/>
              <xs:element name="GRN" type="xs:string"/>
              <xs:element name="CompName" type="xs:string"/>
              <xs:element name="CompCode" type="xs:string"/>
              <xs:element name="BusinessPlace" type="xs:string"/>
            </xs:sequence>
          </xs:complexType>
        </xs:element>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
```

#### 2. Cloud Firestore Collections Layout
| Collection | Key Pattern | Purpose & Access Model |
| :--- | :--- | :--- |
| `invoices` | `{trace_id}` | Primary invoice state store with sanitized Base64 PDF attachment and embedded `cpi_response`. |
| `cpi_responses` | `cpi_{trace_id}_{timestamp}` | Historical append-only audit trail capturing every CPI attempt, parsed fields, and raw payload text. |
| `cpi_responses_by_trace` | `{trace_id}` | Fast $O(1)$ lookup for the latest SAP CPI response per invoice. |
| `audit_logs` | `audit_{timestamp}_{uuid}` | Tamper-evident, SHA-256 hash-chained immutable audit log of all system transitions. |
| `auth_events` | `auth_{timestamp}_{uuid}` | Access logs capturing SSO and corporate user authentications. |
| `incident_alerts` | `inc_{timestamp}_{uuid}` | Incident records delivered dynamically via Microsoft Power Automate and Firebase Extension. |
| `mail` | `{mailId}` | Outbound email queue monitored by the official `firestore-send-email` Firebase Extension. |

#### 3. Dedicated SAP CPI Response Query API
Retrieve the exact recorded SAP CPI response for any processed document:
```bash
curl -X GET "https://sap-invoice-engine-411369932113.us-central1.run.app/api/invoices/{trace_id}/cpi-response" \
  -H "Authorization: Bearer <FIREBASE_ID_TOKEN>"
```
* **Tenant Isolation**: Standard corporate users can only query CPI responses for documents they uploaded. Administrator (`aic1176@aurogroup.com`) can inspect responses across all tenant submissions.

---

### Secret Manager Credentials

Configured in Cloud Run via `--set-secrets`:

| Secret Name | Key | Description |
| :--- | :--- | :--- |
| `SAP_TOKEN_URL:1` | `SAP_TOKEN_URL` | SAP OAuth 2.0 Client Credentials token issuance endpoint. |
| `SAP_CLIENT_ID:1` | `SAP_CLIENT_ID` | OAuth 2.0 client credential identifier. |
| `SAP_CLIENT_SECRET:1` | `SAP_CLIENT_SECRET` | OAuth 2.0 client credential secret. |
| `SAP_CPI_URI:1` | `SAP_CPI_URI` | Inbound SAP CPI HTTP endpoint (`ZMM_VENDORINV_PARK_AUTOMATE`). |

---

## Project Structure

```text
aepl-invoice-automation/
├── .github/
│   └── workflows/
│       └── deploy.yml            # Keyless CI/CD pipeline deploying to Cloud Run via WIF v2
├── AEPL_Invoice_Parking_Automation_Using_Google_ADK.ipynb  # Reference architectural notebook
├── Dockerfile                    # Hardened Python 3.11-slim container with non-root aepluser
├── index.html                    # Universal responsive SAP Fiori Horizon AP web portal
├── main.py                       # Core FastAPI service, Model Armor client, and SAP BAPI dispatcher
├── README.md                     # Technical architecture, setup, and deployment manual
└── requirements.txt              # Pinned production dependencies (FastAPI, GenAI, Model Armor, PyMuPDF)
```
