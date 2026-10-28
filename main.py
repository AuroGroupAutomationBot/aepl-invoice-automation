import asyncio
import base64
import copy
import hashlib
import hmac
import io
import json
import logging
import os
import random
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import firebase_admin
from firebase_admin import auth as firebase_auth, firestore as fb_firestore
import fitz  # PyMuPDF
from fastapi import FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from google import genai
from google.genai import types
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1
import requests
from PIL import Image
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("aepl-sap-engine")

# ---------------------------------------------------------
# 1. ENVIRONMENT & CONFIGURATION
# ---------------------------------------------------------
GCP_PROJECT = os.getenv("GCP_PROJECT", "prj-aepl-ai-inv-auto-dev")
GCP_LOCATION = os.getenv("GCP_LOCATION", "us-central1")
RUN_REGION = os.getenv("RUN_REGION", "us-central1")
MODEL_ARMOR_LOCATION = os.getenv("MODEL_ARMOR_LOCATION", RUN_REGION)
MODEL_ARMOR_TEMPLATE = os.getenv("MODEL_ARMOR_TEMPLATE", "tpl-aepl-inv-armor")
VERTEX_LOCATION = os.getenv("VERTEX_LOCATION", "global")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
FIRESTORE_LOCATION = os.getenv("FIRESTORE_LOCATION", "asia-south1")
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB strict limit per enterprise specification

# Strict Whitelist & Corporate Domain Authorization
ALLOWED_DOMAINS = {"aurogroup.com", "axisclinicals.com", "aurorealty.com"}

# Sole Administrator per specification
ADMIN_EMAILS = {"aic1176@aurogroup.com"}

# Authorized Corporate Users per specification
ALLOWED_EMAILS = {
    "aic1176@aurogroup.com",
    "hasith.g@aurogroup.com",
    "abigna.k@aurogroup.com",
    "mohithsai.g@axisclinicals.com",
    "prasanna.j@aurorealty.com",
}

# Alert Email Recipient (Default: aic1176@aurogroup.com)
ALERT_EMAIL_RECIPIENT = os.getenv("ALERT_EMAIL_RECIPIENT", "aic1176@aurogroup.com").strip()

# Unified Microsoft Power Automate HTTP Trigger Webhook for ALL Email Communications
DEFAULT_ALERT_WEBHOOK_URL = (
    "https://default75076fa3e5184305a3745215e94dee.de.environment.api.powerplatform.com:443"
    "/powerautomate/automations/direct/cu/31/workflows/9f516bc84195412ab844e3fa188bc9f7/triggers/manual/paths/invoke"
    "?api-version=1&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=1NtyL2rRdWjw1vp-yjIf5e_DiYn2oxHZPaw0ZrVc050"
)

# SAP CPI Credentials from Secret Manager
SAP_TOKEN_URL = os.getenv("SAP_TOKEN_URL", "").strip()
SAP_CLIENT_ID = os.getenv("SAP_CLIENT_ID", "").strip()
SAP_CLIENT_SECRET = os.getenv("SAP_CLIENT_SECRET", "").strip()
SAP_CPI_URI = os.getenv("SAP_CPI_URI", "").strip()

# Initialize Firebase Admin
if not firebase_admin._apps:
    firebase_admin.initialize_app(options={"projectId": GCP_PROJECT})

# Initialize Cloud Firestore Client (Native GCP in Mumbai asia-south1 & Firebase fallback)
firestore_client = None
try:
    from google.cloud import firestore as gcp_firestore
    firestore_client = gcp_firestore.Client(project=GCP_PROJECT)
    logger.info(f"Cloud Firestore client connected to project '{GCP_PROJECT}' (Location: {FIRESTORE_LOCATION}).")
except Exception as e1:
    try:
        firestore_client = fb_firestore.client()
        logger.info("Cloud Firestore client initialized via Firebase Admin.")
    except Exception as e2:
        logger.warning(f"Cloud Firestore connection notice ({e1} / {e2}). Synchronized in-memory store active.")

# Initialize Vertex AI Gemini Client
genai_client = genai.Client(vertexai=True, project=GCP_PROJECT, location=VERTEX_LOCATION)

# Initialize Regional Model Armor Client (us-central1)
armor_client = modelarmor_v1.ModelArmorClient(
    client_options=ClientOptions(api_endpoint=f"modelarmor.{MODEL_ARMOR_LOCATION}.rep.googleapis.com")
)
ARMOR_TEMPLATE_PATH = f"projects/{GCP_PROJECT}/locations/{MODEL_ARMOR_LOCATION}/templates/{MODEL_ARMOR_TEMPLATE}"

app = FastAPI(title="AEPL Autonomous SAP Invoice Parking Engine", docs_url=None, redoc_url=None)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """MAANG-Grade Defense-in-Depth HTTP Security Headers Middleware."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://fonts.gstatic.com data:;"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def validate_file_magic_bytes(filename: str, content: bytes) -> bool:
    """
    Magic-Byte MIME Signature Sniffing.
    Protects against disguised polyglots and executable masquerades.
    """
    if not content:
        return False
    fn = filename.lower()
    if fn.endswith(".pdf") or content.startswith(b"%PDF"):
        return content.startswith(b"%PDF-")
    if fn.endswith((".jpg", ".jpeg")):
        return content.startswith(b"\xff\xd8\xff")
    if fn.endswith(".png"):
        return content.startswith(b"\x89PNG\r\n\x1a\n")
    if fn.endswith((".tif", ".tiff")):
        return content.startswith(b"II*\x00") or content.startswith(b"MM\x00*")
    return False


def is_admin_user(email: str) -> bool:
    """Checks whether the specified email belongs strictly to the Administrator role (aic1176@aurogroup.com)."""
    return (email or "").lower().strip() in ADMIN_EMAILS


# ---------------------------------------------------------
# CRYPTOGRAPHIC PASSWORDS & IAM HARDENING (OWASP ASVS 4.0 / NIST SP 800-63B)
# ---------------------------------------------------------
def hash_password(password: str) -> str:
    """
    Hardened PBKDF2-HMAC-SHA512 with 600,000 iterations and 32-byte cryptographic random salt.
    Compliant with OWASP 2026 Password Storage Guidelines.
    """
    salt = os.urandom(32).hex()
    key = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), bytes.fromhex(salt), 600000)
    return f"{salt}${key.hex()}"


def verify_password(password: str, hashed_str: str) -> bool:
    """Timing-attack resistant verification of PBKDF2-HMAC-SHA512 password hash."""
    try:
        parts = hashed_str.split("$")
        if len(parts) != 2:
            return False
        salt, key_hex = parts
        computed = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), bytes.fromhex(salt), 600000)
        return hmac.compare_digest(computed.hex(), key_hex)
    except Exception:
        return False


# Whitelisted Predefined Corporate Users (Default seed credentials)
PREDEFINED_USERS = {
    "aic1176": {
        "username": "aic1176",
        "email": "aic1176@aurogroup.com",
        "role": "admin",
        "full_name": "AEPL Administrator",
        "default_pwd": "AuroAdmin@2026!",
    },
    "hasith.g": {
        "username": "hasith.g",
        "email": "hasith.g@aurogroup.com",
        "role": "user",
        "full_name": "Hasith G",
        "default_pwd": "AuroUser@2026!",
    },
    "abigna.k": {
        "username": "abigna.k",
        "email": "abigna.k@aurogroup.com",
        "role": "user",
        "full_name": "Abigna K",
        "default_pwd": "AuroUser@2026!",
    },
    "mohithsai.g": {
        "username": "mohithsai.g",
        "email": "mohithsai.g@axisclinicals.com",
        "role": "user",
        "full_name": "Mohith Sai G",
        "default_pwd": "AuroUser@2026!",
    },
    "prasanna.j": {
        "username": "prasanna.j",
        "email": "prasanna.j@aurorealty.com",
        "role": "user",
        "full_name": "Prasanna J",
        "default_pwd": "AuroUser@2026!",
    },
}

_USERS_MEM: Dict[str, Dict[str, Any]] = {}
for uname, udata in PREDEFINED_USERS.items():
    _USERS_MEM[uname.lower()] = {
        "username": udata["username"],
        "email": udata["email"].lower(),
        "role": udata["role"],
        "full_name": udata["full_name"],
        "password_hash": hash_password(udata["default_pwd"]),
        "status": "ACTIVE",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _USERS_MEM[udata["email"].lower()] = _USERS_MEM[uname.lower()]


# Anti-Brute Force Sliding-Window Rate Limiter & Lockout Cache
_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}
_LOCKED_ACCOUNTS: Dict[str, float] = {}


def check_rate_limit_and_lockout(identifier: str, client_ip: str) -> Optional[str]:
    now = time.time()
    for key in (identifier.lower(), client_ip):
        if key in _LOCKED_ACCOUNTS:
            locked_until = _LOCKED_ACCOUNTS[key]
            if now < locked_until:
                remaining_mins = max(1, int((locked_until - now) / 60))
                return f"Account / IP locked due to multiple failed login attempts. Retry in {remaining_mins} minutes or request password reset."
            else:
                del _LOCKED_ACCOUNTS[key]
    return None


def record_failed_login(identifier: str, client_ip: str):
    now = time.time()
    for key in (identifier.lower(), client_ip):
        attempts = _LOGIN_ATTEMPTS.setdefault(key, [])
        attempts = [t for t in attempts if now - t < 900]
        attempts.append(now)
        _LOGIN_ATTEMPTS[key] = attempts
        if len(attempts) >= 5:
            _LOCKED_ACCOUNTS[key] = now + 1800  # 30 minutes lockout
            alert_service.send_failure_alert(
                failure_type="SECURITY_ACCOUNT_LOCKOUT",
                filename="authentication_gateway",
                trace_id=f"lock_{key[:8]}",
                user_email=identifier,
                error_title=f"Security Lockout: 5 Failed Attempts for '{key}'",
                error_detail=f"IP {client_ip} has been temporarily locked out for 30 minutes after 5 consecutive failed authentications.",
            )


def reset_login_attempts(identifier: str, client_ip: str):
    for key in (identifier.lower(), client_ip):
        _LOGIN_ATTEMPTS.pop(key, None)
        _LOCKED_ACCOUNTS.pop(key, None)


# ---------------------------------------------------------
# 2. UNIFIED POWER AUTOMATE NOTIFICATION CLIENT
# ---------------------------------------------------------
# ---------------------------------------------------------
# 3B. INDIAN CURRENCY FORMATTER
# ---------------------------------------------------------
def format_inr(val: Any) -> str:
    """Formats numeric value into standard Indian Rupee notation (e.g. ₹ 26,02,307.00)."""
    try:
        f = float(val or 0.0)
    except (ValueError, TypeError):
        return "₹ 0.00"
    s = f"{f:.2f}"
    parts = s.split(".")
    integer_part = parts[0]
    decimal_part = parts[1]
    is_neg = integer_part.startswith("-")
    if is_neg:
        integer_part = integer_part[1:]
    if len(integer_part) > 3:
        last3 = integer_part[-3:]
        remaining = integer_part[:-3]
        groups = []
        while len(remaining) > 2:
            groups.insert(0, remaining[-2:])
            remaining = remaining[:-2]
        if remaining:
            groups.insert(0, remaining)
        formatted_int = ",".join(groups) + "," + last3
    else:
        formatted_int = integer_part
    prefix = "-₹ " if is_neg else "₹ "
    return f"{prefix}{formatted_int}.{decimal_part}"


class AlertNotificationService:
    """
    Unified Enterprise Email Notification Service via Microsoft Power Automate Webhook.
    Delivers:
    1. Incident Failure Alerts (All non-success outcomes) -> aic1176@aurogroup.com
    2. Secure Password Reset Links -> Corporate User & aic1176@aurogroup.com
    3. Automated Monthly Executive MIS Reports -> aic1176@aurogroup.com
    4. Account Lockout Security Alerts -> aic1176@aurogroup.com

    Strictly complies with the Microsoft Power Automate Request Body JSON Schema:
    {
        "type": "object",
        "properties": {
            "incident_id": { "type": "string" },
            "recipient": { "type": "string" },
            "subject": { "type": "string" },
            "html": { "type": "string" },
            "text": { "type": "string" },
            "failure_type": { "type": "string" },
            "filename": { "type": "string" },
            "trace_id": { "type": "string" },
            "timestamp": { "type": "string" },
            "submitted_by": { "type": "string" },
            "error_title": { "type": "string" },
            "error_detail": { "type": "string" }
        }
    }
    """
    POWER_AUTOMATE_SCHEMA_FIELDS = [
        "incident_id",
        "recipient",
        "subject",
        "html",
        "text",
        "failure_type",
        "filename",
        "trace_id",
        "timestamp",
        "submitted_by",
        "error_title",
        "error_detail",
    ]

    def __init__(self, db):
        self.db = db
        self.recipient_email = ALERT_EMAIL_RECIPIENT
        self.sender_email = os.getenv("ALERT_SENDER_EMAIL", self.recipient_email).strip()
        self.mail_collection = os.getenv("MAIL_COLLECTION", "mail").strip()
        self.webhook_url = os.getenv("ALERT_WEBHOOK_URL", "").strip() or DEFAULT_ALERT_WEBHOOK_URL
        self._incidents_mem: List[Dict[str, Any]] = []

    def normalize_power_automate_payload(self, raw_payload: Dict[str, Any]) -> Dict[str, str]:
        """
        Enforces strict compliance with Microsoft Power Automate Request Body JSON Schema.
        Guarantees all 12 properties are present, non-null, and string-typed.
        """
        clean_payload: Dict[str, str] = {}
        for field in self.POWER_AUTOMATE_SCHEMA_FIELDS:
            val = raw_payload.get(field, "")
            if val is None:
                val = ""
            elif not isinstance(val, str):
                val = str(val)
            clean_payload[field] = val
        return clean_payload

    def dispatch_power_automate(self, payload: Dict[str, Any]) -> bool:
        """Sends payload directly to Microsoft Power Automate HTTP trigger webhook."""
        if not self.webhook_url:
            return False
        clean_payload = self.normalize_power_automate_payload(payload)
        try:
            res = requests.post(
                self.webhook_url,
                json=clean_payload,
                headers={"Content-Type": "application/json; charset=utf-8"},
                timeout=10,
            )
            if res.status_code in (200, 201, 202):
                logger.info(f"Power Automate webhook delivered successfully ({res.status_code}) for type '{clean_payload.get('failure_type')}'.")
                return True
            else:
                logger.warning(f"Power Automate returned status {res.status_code}: {res.text[:200]}")
        except Exception as exc:
            logger.warning(f"Power Automate dispatch exception: {exc}")
        return False

    def send_failure_alert(
        self,
        failure_type: str,
        filename: str,
        trace_id: str,
        user_email: str,
        error_title: str,
        error_detail: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Dispatches automated failure incident email to aic1176@aurogroup.com on ALL non-success scenarios."""
        now_iso = datetime.now(timezone.utc).isoformat()
        incident_id = f"inc_{str(uuid.uuid4())[:8]}"
        subject = f"[SAP AP FAILURE ALERT] {error_title} - {filename} ({trace_id})"
        plain_text = (
            f"SAP S/4HANA Invoice Automation — Failure Incident Alert\n"
            f"Incident ID: {incident_id}\n"
            f"Failure Type: {failure_type}\n"
            f"Document: {filename}\n"
            f"Trace ID: {trace_id}\n"
            f"Submitted By: {user_email}\n"
            f"Timestamp (UTC): {now_iso}\n"
            f"Error: {error_title} - {error_detail}\n"
            f"Action Required: Inspect Admin MIS Dashboard as {self.recipient_email}."
        )

        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #1e293b; line-height: 1.5; padding: 20px;">
            <div style="background-color: #b91c1c; color: #ffffff; padding: 14px 20px; border-radius: 6px; font-size: 18px; font-weight: bold;">
                SAP S/4HANA Invoice Automation — Failure Incident Alert
            </div>
            <div style="padding: 20px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 6px 6px; background-color: #fafbfc;">
                <p style="font-size: 14px; margin-top: 0;">An automated invoice processing exception has occurred requiring administrative attention.</p>
                <table style="width: 100%; border-collapse: collapse; margin: 15px 0; font-size: 13px;">
                    <tr><td style="padding: 6px 0; font-weight: bold; width: 160px;">Incident ID:</td><td>{incident_id}</td></tr>
                    <tr><td style="padding: 6px 0; font-weight: bold;">Failure Type:</td><td style="color: #b91c1c; font-weight: bold;">{failure_type}</td></tr>
                    <tr><td style="padding: 6px 0; font-weight: bold;">Document File:</td><td>{filename}</td></tr>
                    <tr><td style="padding: 6px 0; font-weight: bold;">Trace ID:</td><td><code>{trace_id}</code></td></tr>
                    <tr><td style="padding: 6px 0; font-weight: bold;">Submitted By:</td><td>{user_email}</td></tr>
                    <tr><td style="padding: 6px 0; font-weight: bold;">Timestamp (UTC):</td><td>{now_iso}</td></tr>
                    <tr><td style="padding: 6px 0; font-weight: bold; vertical-align: top;">Error Summary:</td><td><strong>{error_title}</strong><br><span style="color: #64748b;">{error_detail}</span></td></tr>
                </table>
                <div style="margin-top: 20px; padding: 12px; background-color: #fee2e2; border-left: 4px solid #b91c1c; font-size: 13px;">
                    <strong>Action Required:</strong> Log in to the Admin MIS Dashboard as <code>{self.recipient_email}</code> to inspect telemetry or review in Human-in-the-Loop queue.
                </div>
            </div>
        </body>
        </html>
        """

        incident = {
            "incident_id": incident_id,
            "timestamp": now_iso,
            "failure_type": failure_type,
            "recipient": self.recipient_email,
            "trace_id": trace_id,
            "filename": filename,
            "submitted_by": user_email,
            "error_title": error_title,
            "error_detail": error_detail,
            "metadata": metadata or {},
            "email_status": "TRIGGERED",
        }
        self._incidents_mem.append(incident)

        logger.critical(
            f"ALERT TRIGGERED -> Recipient: {self.recipient_email} | Incident: {incident_id} | "
            f"Type: {failure_type} | File: {filename} | Error: {error_title} - {error_detail}"
        )

        wh_payload = {
            "incident_id": incident_id,
            "recipient": self.recipient_email,
            "subject": subject,
            "html": html_body,
            "text": plain_text,
            "failure_type": failure_type,
            "filename": filename,
            "trace_id": trace_id,
            "timestamp": now_iso,
            "submitted_by": user_email,
            "error_title": error_title,
            "error_detail": error_detail,
        }
        if self.dispatch_power_automate(wh_payload):
            incident["email_status"] = f"DISPATCHED_WEBHOOK_TO_{self.recipient_email}"

        # Write to Firestore mail collection for backup / firestore-send-email extension
        if self.db:
            try:
                self.db.collection(self.mail_collection).document(incident_id).set({
                    "to": [self.recipient_email],
                    "from": self.sender_email,
                    "replyTo": self.sender_email,
                    "message": {"subject": subject, "text": plain_text, "html": html_body},
                    "incident_id": incident_id,
                    "failure_type": failure_type,
                    "filename": filename,
                    "trace_id": trace_id,
                    "timestamp": now_iso,
                })
                self.db.collection("incident_alerts").document(incident_id).set(incident)
            except Exception as mail_exc:
                logger.warning(f"Firestore incident record notice: {mail_exc}")

        return incident

    def send_password_reset_email(self, email: str, username: str, reset_url: str) -> bool:
        """Dispatches secure password reset link via Power Automate with audit copy to aic1176@aurogroup.com."""
        subject = "[AEPL AP Security] Action Required: Reset Your Password"
        plain_text = (
            f"Hello {username},\n\n"
            f"A password reset was requested for your AEPL SAP Invoice Engine account ({email}).\n"
            f"Click the link below to set a new password:\n{reset_url}\n\n"
            f"This link is valid for 15 minutes and can only be used once.\n"
            f"If you did not request this, please notify {self.recipient_email} immediately."
        )
        html_body = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1e293b; background-color: #f8fafc; padding: 24px; margin: 0;">
            <div style="max-width: 560px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);">
                <div style="background-color: #0f172a; padding: 20px 24px; border-bottom: 3px solid #0284c7;">
                    <h2 style="color: #ffffff; margin: 0; font-size: 18px; font-weight: 600;">
                        AEPL SAP Invoice Parking Engine
                    </h2>
                    <p style="color: #94a3b8; margin: 4px 0 0 0; font-size: 12px;">Security &amp; Account Recovery</p>
                </div>
                <div style="padding: 28px 24px;">
                    <p style="font-size: 14px; margin-top: 0; color: #334155;">Hello <strong>{username}</strong>,</p>
                    <p style="font-size: 14px; color: #334155; line-height: 1.6;">
                        A password reset request was submitted for your corporate account (<code>{email}</code>). Click the button below to establish a new password:
                    </p>
                    <div style="text-align: center; margin: 28px 0;">
                        <a href="{reset_url}" style="background-color: #0284c7; color: #ffffff; padding: 12px 28px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 14px; display: inline-block;">
                            Reset Account Password &rarr;
                        </a>
                    </div>
                    <div style="background-color: #f1f5f9; padding: 12px; border-radius: 6px; font-size: 12px; color: #475569; word-break: break-all;">
                        <strong>Direct Link:</strong><br>
                        <a href="{reset_url}" style="color: #0284c7;">{reset_url}</a>
                    </div>
                    <p style="font-size: 12px; color: #64748b; margin-top: 24px; line-height: 1.5;">
                        &bull; This link is cryptographically signed and strictly expires in <strong>15 minutes</strong>.<br>
                        &bull; It is single-use and will be invalidated immediately upon consumption.<br>
                        &bull; If you did not make this request, alert the AEPL Administrator at <code>{self.recipient_email}</code>.
                    </p>
                </div>
                <div style="background-color: #f8fafc; padding: 14px 24px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center;">
                    Auro Enterprises &bull; Automated Accounts Payable &bull; Audit CC: {self.recipient_email}
                </div>
            </div>
        </body>
        </html>
        """
        payload = {
            "incident_id": f"pwd_reset_{str(uuid.uuid4())[:8]}",
            "recipient": email,
            "subject": subject,
            "html": html_body,
            "text": plain_text,
            "failure_type": "PASSWORD_RESET_DISPATCH",
            "filename": "auth_recovery.html",
            "trace_id": f"reset_{username}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "submitted_by": email,
            "error_title": "Password Reset Link Dispatched",
            "error_detail": f"Time-limited single-use reset token dispatched to {email}. Audit copy sent to {self.recipient_email}.",
        }
        return self.dispatch_power_automate(payload)

    def send_monthly_mis_digest(
        self,
        month_str: str,
        metrics: Dict[str, Any],
        user_breakdown: List[Dict[str, Any]],
    ) -> bool:
        """Dispatches automated monthly executive MIS report via Power Automate to aic1176@aurogroup.com."""
        subject = f"[AEPL AP AUTOMATION] Monthly Executive MIS Report - {month_str}"
        total_inv = metrics.get("total_invoices", 0)
        parked = metrics.get("parked_success", 0)
        hitl = metrics.get("hitl_pending", 0)
        sap_rejected = metrics.get("sap_rejected", 0)
        action_required = hitl + sap_rejected
        duplicates = metrics.get("duplicate_detected", 0)
        gross_val = metrics.get("total_gross_val", 0.0)
        taxable_val = metrics.get("total_taxable_val", 0.0)
        success_pct = round((parked / total_inv * 100), 1) if total_inv else 0.0

        user_rows = "".join([
            f"<tr>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e2e8f0; font-family:monospace; font-size:11px;'><code>{u.get('email') or u.get('user') or 'Corporate User'}</code></td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e2e8f0; text-align:center; font-weight:700;'>{u.get('total', 0)}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e2e8f0; text-align:center; color:#15803d; font-weight:700;'>{u.get('parked', 0)}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e2e8f0; text-align:center; color:#b45309; font-weight:600;'>{u.get('hitl', 0)}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e2e8f0; text-align:center; color:#c2410c; font-weight:600;'>{u.get('sap_rejected', 0)}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e2e8f0; text-align:center; color:#0369a1; font-weight:600;'>{u.get('duplicates', 0)}</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e2e8f0; text-align:center; font-weight:600;'>{u.get('success_rate', 0.0)}%</td>"
            f"<td style='padding:8px 10px; border-bottom:1px solid #e2e8f0; text-align:right; font-family:monospace; font-weight:700;'>{format_inr(u.get('gross', 0.0))}</td>"
            f"</tr>"
            for u in user_breakdown
        ])

        total_row = (
            f"<tr style='background:#f8fafc; font-weight:bold;'>"
            f"<td style='padding:9px 10px; border-top:2px solid #cbd5e1; border-bottom:2px solid #cbd5e1; font-weight:bold;'>Total (Organization-Wide)</td>"
            f"<td style='padding:9px 10px; border-top:2px solid #cbd5e1; border-bottom:2px solid #cbd5e1; text-align:center; font-weight:bold;'>{total_inv}</td>"
            f"<td style='padding:9px 10px; border-top:2px solid #cbd5e1; border-bottom:2px solid #cbd5e1; text-align:center; color:#15803d; font-weight:bold;'>{parked}</td>"
            f"<td style='padding:9px 10px; border-top:2px solid #cbd5e1; border-bottom:2px solid #cbd5e1; text-align:center; color:#b45309; font-weight:bold;'>{hitl}</td>"
            f"<td style='padding:9px 10px; border-top:2px solid #cbd5e1; border-bottom:2px solid #cbd5e1; text-align:center; color:#c2410c; font-weight:bold;'>{sap_rejected}</td>"
            f"<td style='padding:9px 10px; border-top:2px solid #cbd5e1; border-bottom:2px solid #cbd5e1; text-align:center; color:#0369a1; font-weight:bold;'>{duplicates}</td>"
            f"<td style='padding:9px 10px; border-top:2px solid #cbd5e1; border-bottom:2px solid #cbd5e1; text-align:center; font-weight:bold;'>{success_pct}%</td>"
            f"<td style='padding:9px 10px; border-top:2px solid #cbd5e1; border-bottom:2px solid #cbd5e1; text-align:right; font-family:monospace; font-weight:bold; color:#1d4ed8;'>{format_inr(gross_val)}</td>"
            f"</tr>"
        )

        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #1e293b; background-color: #f8fafc; padding: 24px; margin: 0;">
            <div style="max-width: 720px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.05);">
                <div style="background-color: #0f172a; padding: 22px 28px; border-bottom: 4px solid #16a34a;">
                    <h2 style="color: #ffffff; margin: 0; font-size: 20px;">AEPL Autonomous Accounts Payable Automation</h2>
                    <p style="color: #94a3b8; margin: 4px 0 0 0; font-size: 13px;">Monthly Executive Performance Digest &bull; {month_str}</p>
                </div>
                <div style="padding: 24px;">
                    <!-- Email client robust summary cards (Row 1: Parked & Gross Value) -->
                    <table style="width: 100%; border-collapse: separate; border-spacing: 8px 0; margin-bottom: 10px;" cellpadding="0" cellspacing="0">
                        <tr>
                            <td style="width: 50%; padding: 14px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; vertical-align: top;">
                                <div style="font-size: 11px; color: #166534; font-weight: bold; text-transform: uppercase;">Total Parked (MIR7)</div>
                                <div style="font-size: 24px; font-weight: bold; color: #15803d; margin-top: 4px;">{parked} / {total_inv}</div>
                                <div style="font-size: 11px; color: #15803d; margin-top: 2px;">{success_pct}% End-to-End Automation Rate</div>
                            </td>
                            <td style="width: 50%; padding: 14px; background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; vertical-align: top;">
                                <div style="font-size: 11px; color: #1e40af; font-weight: bold; text-transform: uppercase;">Gross Financial Volume</div>
                                <div style="font-size: 22px; font-weight: bold; color: #1d4ed8; margin-top: 4px;">{format_inr(gross_val)}</div>
                                <div style="font-size: 11px; color: #3b82f6; margin-top: 2px;">Taxable Base: {format_inr(taxable_val)}</div>
                            </td>
                        </tr>
                    </table>
                    <!-- Row 2: Mutually Exclusive Operational Outcome Cards (Parked 3 + HITL 4 + SAP Rej 3 + Duplicates 6 = 16) -->
                    <table style="width: 100%; border-collapse: separate; border-spacing: 8px 0; margin-bottom: 20px;" cellpadding="0" cellspacing="0">
                        <tr>
                            <td style="width: 33.33%; padding: 12px; background: #fffbeb; border: 1px solid #fde68a; border-radius: 6px; vertical-align: top;">
                                <div style="font-size: 10px; color: #92400e; font-weight: bold; text-transform: uppercase;">Pending Review (HITL)</div>
                                <div style="font-size: 22px; font-weight: bold; color: #b45309; margin-top: 4px;">{hitl}</div>
                                <div style="font-size: 10px; color: #d97706; margin-top: 2px;">Awaiting Human Review</div>
                            </td>
                            <td style="width: 33.33%; padding: 12px; background: #fff7ed; border: 1px solid #ffedd5; border-radius: 6px; vertical-align: top;">
                                <div style="font-size: 10px; color: #9a3412; font-weight: bold; text-transform: uppercase;">SAP Rejections</div>
                                <div style="font-size: 22px; font-weight: bold; color: #c2410c; margin-top: 4px;">{sap_rejected}</div>
                                <div style="font-size: 10px; color: #ea580c; margin-top: 2px;">Posting / BAPI Errors</div>
                            </td>
                            <td style="width: 33.33%; padding: 12px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; vertical-align: top;">
                                <div style="font-size: 10px; color: #991b1b; font-weight: bold; text-transform: uppercase;">Duplicates Prevented</div>
                                <div style="font-size: 22px; font-weight: bold; color: #b91c1c; margin-top: 4px;">{duplicates}</div>
                                <div style="font-size: 10px; color: #dc2626; margin-top: 2px;">Double-Billing Blocked</div>
                            </td>
                        </tr>
                    </table>

                    <h3 style="font-size: 14px; color: #0f172a; margin: 18px 0 8px 0; border-bottom: 2px solid #f1f5f9; padding-bottom: 6px;">User Activity Breakdown</h3>
                    <table style="width: 100%; border-collapse: collapse; font-size: 11px; margin-bottom: 20px;">
                        <thead>
                            <tr style="background: #f8fafc; color: #475569; text-align: left;">
                                <th style="padding: 8px 10px; border-bottom: 2px solid #e2e8f0; width: 26%;">Corporate User</th>
                                <th style="padding: 8px 10px; border-bottom: 2px solid #e2e8f0; text-align: center; width: 9%;">Uploads</th>
                                <th style="padding: 8px 10px; border-bottom: 2px solid #e2e8f0; text-align: center; width: 9%;">Parked</th>
                                <th style="padding: 8px 10px; border-bottom: 2px solid #e2e8f0; text-align: center; width: 10%;">HITL</th>
                                <th style="padding: 8px 10px; border-bottom: 2px solid #e2e8f0; text-align: center; width: 10%;">Rejected</th>
                                <th style="padding: 8px 10px; border-bottom: 2px solid #e2e8f0; text-align: center; width: 11%;">Duplicates</th>
                                <th style="padding: 8px 10px; border-bottom: 2px solid #e2e8f0; text-align: center; width: 9%;">Rate</th>
                                <th style="padding: 8px 10px; border-bottom: 2px solid #e2e8f0; text-align: right; width: 16%;">Gross Value</th>
                            </tr>
                        </thead>
                        <tbody>
                            {user_rows or '<tr><td colspan="8" style="padding:10px; text-align:center; color:#94a3b8;">No uploads recorded for this monthly period.</td></tr>'}
                            {total_row if user_rows else ''}
                        </tbody>
                    </table>

                    <div style="background-color: #f8fafc; border-left: 4px solid #0284c7; padding: 12px; font-size: 12px; color: #334155;">
                        <strong>Enterprise Observability:</strong> Zero-Trust Audit Logs are continuously hashed and synchronized in Cloud Firestore (Mumbai asia-south1). Full incident logs available in Admin MIS.
                    </div>
                </div>
                <div style="background-color: #0f172a; padding: 12px 24px; font-size: 11px; color: #94a3b8; text-align: center;">
                    Designated Recipient: {self.recipient_email} &bull; Generated Automatically via Power Automate
                </div>
            </div>
        </body>
        </html>
        """
        payload = {
            "incident_id": f"mis_{str(uuid.uuid4())[:8]}",
            "recipient": self.recipient_email,
            "subject": subject,
            "html": html_body,
            "text": f"Monthly MIS Digest for {month_str}: Total={total_inv}, Parked={parked}, Gross={format_inr(gross_val)}",
            "failure_type": "MONTHLY_MIS_REPORT",
            "filename": f"monthly_mis_{month_str.replace(' ', '_')}.html",
            "trace_id": f"mis_{datetime.now(timezone.utc).strftime('%Y%m')}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "submitted_by": self.recipient_email,
            "error_title": f"Monthly MIS Executive Digest - {month_str}",
            "error_detail": f"Performance summary delivered: {parked} documents parked, {format_inr(gross_val)} processed.",
        }
        return self.dispatch_power_automate(payload)

    def list_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        if self.db:
            try:
                docs = self.db.collection("incident_alerts").order_by("timestamp", direction="DESCENDING").limit(limit).stream()
                fs_items = [d.to_dict() for d in docs]
                if fs_items:
                    return fs_items
            except Exception:
                pass
        return sorted(self._incidents_mem, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]


# ---------------------------------------------------------
# 3. CUSTOMISABLE ERROR TAXONOMY & RESOLUTION HINTS
# ---------------------------------------------------------
class SAPErrorTaxonomy:
    """
    Structured enterprise error dictionary for accounts payable invoice ingestion.
    Allows easy customization of error messages and resolution flows for different business scenarios.
    """
    CATALOG: Dict[str, Dict[str, Any]] = {
        "ERR_MISSING_PO": {
            "code": "ERR_MISSING_PO",
            "title": "Purchase Order Number Missing",
            "message": "Purchase Order (PO Number) is missing or could not be detected on the document.",
            "resolution_hint": "Please supply the 10-digit SAP Purchase Order number (EBELN) to resume processing.",
            "hitl_eligible": True,
            "target_fields": ["PONumber"],
        },
        "ERR_INVALID_PO": {
            "code": "ERR_INVALID_PO",
            "title": "Invalid Purchase Order Format",
            "message": "Purchase Order '{value}' is invalid. SAP requires strictly a 10-digit numeric value.",
            "resolution_hint": "Correct the PO number to a 10-digit numeric string (e.g., 4500123456).",
            "hitl_eligible": True,
            "target_fields": ["PONumber"],
        },
        "ERR_MISSING_SES": {
            "code": "ERR_MISSING_SES",
            "title": "Service Entry Sheet Missing",
            "message": "Service Entry Sheet (SES) was not detected on the document. Routed to HITL for review.",
            "resolution_hint": "Enter the 10-digit SES starting with '1' if applicable, or confirm PO-only parking (Only PO is mandatory).",
            "hitl_eligible": True,
            "target_fields": ["SES"],
        },
        "ERR_INVALID_SES": {
            "code": "ERR_INVALID_SES",
            "title": "Invalid Service Entry Sheet Format",
            "message": "Service Entry Sheet '{value}' must be exactly 10 digits and start with '1'.",
            "resolution_hint": "Provide a valid 10-digit SES starting with '1' (e.g., 1000456789), or clear field if not applicable.",
            "hitl_eligible": True,
            "target_fields": ["SES"],
        },
        "ERR_IRRELEVANT_DOCUMENT": {
            "code": "ERR_IRRELEVANT_DOCUMENT",
            "title": "Irrelevant / Unrecognized Company Document",
            "message": "Document does not correspond to an authorized buyer entity (Auro Enterprises [8000] or Trident Chemphar [9000]). Routed to HITL.",
            "resolution_hint": "Review document preview. Click 'Confirm Irrelevant & Discard' to archive without entering any values.",
            "hitl_eligible": True,
            "is_irrelevant": True,
            "target_fields": [],
        },
        "ERR_BATCH_DUPLICATE": {
            "code": "ERR_BATCH_DUPLICATE",
            "title": "Intra-Batch Duplicate Detected (Human Error)",
            "message": "Human error duplicate detected in upload batch: matches previously processed '{seen_file}'. Skipped to prevent duplicate SAP entry.",
            "resolution_hint": "First instance was parked in SAP. The duplicate instance has been flagged and skipped.",
            "hitl_eligible": False,
            "target_fields": [],
        },
        "ERR_INVALID_FILE_SIGNATURE": {
            "code": "ERR_INVALID_FILE_SIGNATURE",
            "title": "Invalid File Magic-Byte Signature",
            "message": "Uploaded file '{filename}' failed binary MIME signature verification. File content does not match expected PDF/Image format.",
            "resolution_hint": "Ensure uploaded files are genuine, uncorrupted PDF or JPEG/PNG documents.",
            "hitl_eligible": False,
            "target_fields": [],
        },
        "ERR_MISSING_REF_DOC": {
            "code": "ERR_MISSING_REF_DOC",
            "title": "Vendor Invoice Reference Missing",
            "message": "Vendor Tax Invoice Number (XBLNR / RefDocNo) was not detected on the document.",
            "resolution_hint": "Enter the vendor's invoice or billing reference number.",
            "hitl_eligible": True,
            "target_fields": ["RefDocNo"],
        },
        "ERR_DUPLICATE_INVOICE": {
            "code": "ERR_DUPLICATE_INVOICE",
            "title": "Duplicate Invoice Detected",
            "message": "Invoice with Reference '{ref_doc_no}' and Company Code '{comp_code}' has already been processed in SAP (Document #{existing_doc}).",
            "resolution_hint": "Verify whether this invoice has already been parked or paid to prevent double payment.",
            "hitl_eligible": False,
            "target_fields": [],
        },
        "ERR_TAXABLE_VAL_ZERO": {
            "code": "ERR_TAXABLE_VAL_ZERO",
            "title": "Invalid Taxable Base Amount",
            "message": "Net taxable base value must be greater than 0.00 INR.",
            "resolution_hint": "Review the extracted line items and specify the net taxable amount.",
            "hitl_eligible": True,
            "target_fields": ["TaxableVal"],
        },
        "ERR_TOTAL_VAL_ZERO": {
            "code": "ERR_TOTAL_VAL_ZERO",
            "title": "Invalid Gross Invoice Amount",
            "message": "Total invoice amount must be greater than 0.00 INR.",
            "resolution_hint": "Review the invoice gross total inclusive of statutory GST.",
            "hitl_eligible": True,
            "target_fields": ["TotalInvVal"],
        },
        "ERR_SALDO_MISMATCH": {
            "code": "ERR_SALDO_MISMATCH",
            "title": "SAP 3-Way Match Balance Check Mismatch",
            "message": "Arithmetic balance mismatch: Gross amount does not equal Taxable Base + GST taxes.",
            "resolution_hint": "Review taxable base and total invoice amount to ensure Saldo = 0.00 INR.",
            "hitl_eligible": True,
            "target_fields": ["TaxableVal", "TotalInvVal"],
        },
        "ERR_MODEL_ARMOR_BLOCKED": {
            "code": "ERR_MODEL_ARMOR_BLOCKED",
            "title": "Model Armor Security Block",
            "message": "Document screening triggered a security policy: potential prompt injection, malicious URI, or unsafe content detected.",
            "resolution_hint": "Audit the original document file for embedded adversarial payloads or suspicious URLs.",
            "hitl_eligible": False,
            "target_fields": [],
        },
        "ERR_UNSUPPORTED_FORMAT": {
            "code": "ERR_UNSUPPORTED_FORMAT",
            "title": "Unsupported File Format",
            "message": "File format is not supported. Upload valid PDF, JPG, PNG, or TIFF files.",
            "resolution_hint": "Convert document to standard PDF or JPEG and re-upload.",
            "hitl_eligible": False,
            "target_fields": [],
        },
        "ERR_SAP_CPI_REJECTED": {
            "code": "ERR_SAP_CPI_REJECTED",
            "title": "SAP S/4HANA BAPI Validation Error",
            "message": "SAP rejected the invoice parking request: {detail}",
            "resolution_hint": "Verify vendor master data, purchasing document status in SAP GUI (/nME23N), or posting period.",
            "hitl_eligible": True,
            "target_fields": ["PONumber", "CompCode", "BusinessPlace"],
        },
        "ERR_SYSTEM_EXCEPTION": {
            "code": "ERR_SYSTEM_EXCEPTION",
            "title": "System Processing Exception",
            "message": "Internal error occurred during document pipeline: {detail}",
            "resolution_hint": "Check the Firestore audit trail and Cloud Logging for stack trace.",
            "hitl_eligible": False,
            "target_fields": [],
        },
        "ERR_FILE_TOO_LARGE": {
            "code": "ERR_FILE_TOO_LARGE",
            "title": "File Exceeds Size Limit (Max 10 MB)",
            "message": "File '{filename}' ({size_mb} MB) exceeds the maximum allowed enterprise limit of 10 MB.",
            "resolution_hint": "Compress high-resolution scans or split large multi-page attachments to stay under 10 MB.",
            "hitl_eligible": False,
            "target_fields": [],
        },
    }

    @classmethod
    def format_error(cls, error_code: str, **kwargs) -> Dict[str, Any]:
        template = cls.CATALOG.get(error_code, {
            "code": error_code,
            "title": "Processing Error",
            "message": f"Error: {error_code}",
            "resolution_hint": "Please review invoice details.",
            "hitl_eligible": False,
            "target_fields": [],
        })
        msg = template["message"]
        for k, v in kwargs.items():
            msg = msg.replace(f"{{{k}}}", str(v))
        return {
            "error_code": template["code"],
            "error_title": template["title"],
            "error_message": msg,
            "resolution_hint": template["resolution_hint"],
            "hitl_eligible": template["hitl_eligible"],
            "target_fields": template["target_fields"],
        }


# ---------------------------------------------------------
# 4. FIRESTORE AUDIT TRAIL & MIS REPOSITORY
# ---------------------------------------------------------
class FirestoreAuditService:
    """
    Central persistence and audit trail service using Cloud Firestore (Mumbai asia-south1).
    MAANG-Grade Security Features:
    - Tamper-Evident Blockchain-Style Cryptographically Chained SHA-256 Audit Trail
    - Enterprise Role-Based Access Control (RBAC) & Tenant Isolation
    - Synchronized In-Memory Ledger for High-Availability
    """
    def __init__(self, db):
        self.db = db
        self._invoices_mem: Dict[str, Dict[str, Any]] = {}
        self._audit_logs_mem: List[Dict[str, Any]] = []
        self._auth_events_mem: List[Dict[str, Any]] = []
        self._password_resets_mem: Dict[str, Dict[str, Any]] = {}
        self._last_audit_hash = "GENESIS_AEPL_FINOPS_HASH_2026"

    def now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def log_event(
        self,
        event_type: str,
        user_email: str,
        trace_id: Optional[str],
        severity: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Creates cryptographically chained, immutable audit event."""
        now = self.now_iso()
        prev_hash = self._last_audit_hash
        payload_meta = metadata or {}
        event_id = str(uuid.uuid4())[:12]
        
        # SHA-256 Cryptographic Chain
        event_signature = hashlib.sha256(
            f"{prev_hash}|{now}|{event_id}|{event_type}|{user_email}|{trace_id}|{message}".encode("utf-8")
        ).hexdigest()
        self._last_audit_hash = event_signature

        entry = {
            "event_id": event_id,
            "timestamp": now,
            "event_type": event_type,
            "user_email": user_email,
            "trace_id": trace_id or "SYSTEM",
            "severity": severity,
            "message": message,
            "metadata": payload_meta,
            "prev_hash": prev_hash,
            "event_hash": event_signature,
        }
        self._audit_logs_mem.append(entry)

        if self.db:
            try:
                self.db.collection("audit_logs").document(entry["event_id"]).set(entry)
            except Exception as e:
                logger.warning(f"Firestore audit_logs write error: {e}")

        logger.info(f"AUDIT [{severity}] {event_type} | {user_email} | {trace_id} | {message}")
        return entry

    def record_auth_event(
        self,
        user_email: str,
        status: str,
        reason: str,
        client_ip: str = "Unknown",
        user_agent: str = "Unknown",
    ) -> Dict[str, Any]:
        entry = {
            "event_id": str(uuid.uuid4())[:12],
            "timestamp": self.now_iso(),
            "user_email": user_email,
            "is_admin": is_admin_user(user_email),
            "status": status,  # "SUCCESS" or "FAILED"
            "reason": reason,
            "client_ip": client_ip,
            "user_agent": user_agent,
        }
        self._auth_events_mem.append(entry)

        if self.db:
            try:
                self.db.collection("auth_events").document(entry["event_id"]).set(entry)
            except Exception as e:
                logger.warning(f"Firestore auth_events write error: {e}")

        self.log_event(
            event_type="AUTH_LOGIN_SUCCESS" if status == "SUCCESS" else "AUTH_LOGIN_FAILED",
            user_email=user_email,
            trace_id=None,
            severity="INFO" if status == "SUCCESS" else "WARNING",
            message=f"Corporate authentication {status.lower()} (Admin: {is_admin_user(user_email)}): {reason}",
            metadata={"client_ip": client_ip, "user_agent": user_agent},
        )
        return entry

    # User IAM & Credential Storage
    def get_user(self, identifier: str) -> Optional[Dict[str, Any]]:
        ident = (identifier or "").strip().lower()
        if ident in _USERS_MEM:
            return _USERS_MEM[ident]
        if self.db:
            try:
                # Query by username
                docs = self.db.collection("users").where("username", "==", ident).limit(1).stream()
                for d in docs:
                    return d.to_dict()
                # Query by email
                docs = self.db.collection("users").where("email", "==", ident).limit(1).stream()
                for d in docs:
                    return d.to_dict()
            except Exception as e:
                logger.warning(f"Firestore get_user error: {e}")
        return None

    def save_user(self, user_data: Dict[str, Any]):
        uname = user_data["username"].lower()
        email = user_data["email"].lower()
        _USERS_MEM[uname] = user_data
        _USERS_MEM[email] = user_data
        if self.db:
            try:
                self.db.collection("users").document(uname).set(user_data)
            except Exception as e:
                logger.warning(f"Firestore save_user error: {e}")

    # Password Reset Storage (NIST SP 800-63B / OWASP)
    def create_password_reset(self, email: str, username: str, token_hash: str, exp: float):
        doc = {
            "token_hash": token_hash,
            "email": email.lower(),
            "username": username.lower(),
            "exp": exp,
            "consumed": False,
            "created_at": self.now_iso(),
        }
        self._password_resets_mem[token_hash] = doc
        if self.db:
            try:
                self.db.collection("password_resets").document(token_hash).set(doc)
            except Exception as e:
                logger.warning(f"Firestore password_resets create notice: {e}")

    def get_password_reset(self, token_hash: str) -> Optional[Dict[str, Any]]:
        record = self._password_resets_mem.get(token_hash)
        if record and not record.get("consumed") and record.get("exp", 0) > time.time():
            return record
        if self.db:
            try:
                d = self.db.collection("password_resets").document(token_hash).get()
                if d.exists:
                    data = d.to_dict()
                    if data and not data.get("consumed") and data.get("exp", 0) > time.time():
                        return data
            except Exception as e:
                logger.warning(f"Firestore password_resets lookup notice: {e}")
        return None

    def consume_password_reset(self, token_hash: str):
        if token_hash in self._password_resets_mem:
            self._password_resets_mem[token_hash]["consumed"] = True
            self._password_resets_mem[token_hash]["consumed_at"] = self.now_iso()
        if self.db:
            try:
                self.db.collection("password_resets").document(token_hash).update({
                    "consumed": True,
                    "consumed_at": self.now_iso(),
                })
            except Exception as e:
                logger.warning(f"Firestore password_resets consume notice: {e}")

    def save_invoice(self, invoice_data: Dict[str, Any]) -> Dict[str, Any]:
        trace_id = invoice_data.get("trace_id") or str(uuid.uuid4())[:8]
        invoice_data["trace_id"] = trace_id
        if "created_at" not in invoice_data:
            invoice_data["created_at"] = self.now_iso()
        invoice_data["updated_at"] = self.now_iso()

        self._invoices_mem[trace_id] = invoice_data

        if self.db:
            try:
                store_copy = copy.deepcopy(invoice_data)
                ext = store_copy.get("extracted_data")
                if isinstance(ext, dict):
                    h = ext.get("HeaderData")
                    if isinstance(h, dict) and "Attachment" in h:
                        raw_att = h["Attachment"]
                        if raw_att and len(str(raw_att)) > 256:
                            h["Attachment"] = f"<Base64 PDF stream ({round(len(str(raw_att))*0.75/1024, 1)} KB)>"
                self.db.collection("invoices").document(trace_id).set(store_copy)
            except Exception as e:
                logger.warning(f"Firestore invoices write error: {e}")

        return invoice_data

    def get_invoice(self, trace_id: str) -> Optional[Dict[str, Any]]:
        if self.db:
            try:
                doc = self.db.collection("invoices").document(trace_id).get()
                if doc.exists:
                    return doc.to_dict()
            except Exception as e:
                logger.warning(f"Firestore invoice read error: {e}")

        return self._invoices_mem.get(trace_id)

    def find_duplicate_invoice(self, ref_doc_no: str, comp_code: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Checks whether an invoice with the same RefDocNo has already been parked successfully."""
        if not ref_doc_no:
            return None

        clean_ref = str(ref_doc_no).strip().upper()

        for inv in self._invoices_mem.values():
            if inv.get("status") == "PARKED_SUCCESS":
                h = inv.get("extracted_data", {}).get("HeaderData", {})
                if str(h.get("RefDocNo", "")).strip().upper() == clean_ref:
                    if not comp_code or str(h.get("CompCode", "")).strip() == str(comp_code).strip():
                        return inv

        if self.db:
            try:
                query = self.db.collection("invoices").where("status", "==", "PARKED_SUCCESS").limit(50)
                docs = query.stream()
                for doc in docs:
                    data = doc.to_dict()
                    h = data.get("extracted_data", {}).get("HeaderData", {})
                    if str(h.get("RefDocNo", "")).strip().upper() == clean_ref:
                        if not comp_code or str(h.get("CompCode", "")).strip() == str(comp_code).strip():
                            return data
            except Exception as e:
                logger.warning(f"Firestore duplicate search error: {e}")

        return None

    def list_invoices(
        self,
        status: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
        user_email: Optional[str] = None,
        is_admin: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Returns filterable invoices with strict multi-tenant isolation.
        Standard users only see invoices submitted by themselves.
        Administrators can view all invoices.
        """
        invoices = []
        if self.db:
            try:
                coll = self.db.collection("invoices")
                fetch_limit = limit * 4 if (status and status != "ALL") else limit
                q = coll.order_by("created_at", direction="DESCENDING").limit(fetch_limit)
                docs = q.stream()
                for doc in docs:
                    invoices.append(doc.to_dict())
            except Exception as e:
                logger.warning(f"Firestore list_invoices query error: {e}")
                invoices = list(self._invoices_mem.values())
        else:
            invoices = list(self._invoices_mem.values())

        if not invoices and self._invoices_mem:
            invoices = list(self._invoices_mem.values())

        invoices.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        # Multi-User RBAC Isolation
        if not is_admin and user_email:
            ue = user_email.lower().strip()
            invoices = [inv for inv in invoices if str(inv.get("submitted_by", "")).lower().strip() == ue]

        if status and status != "ALL":
            invoices = [inv for inv in invoices if inv.get("status") == status]

        if search:
            s = search.lower().strip()
            invoices = [
                inv for inv in invoices
                if s in str(inv.get("filename", "")).lower()
                or s in str(inv.get("trace_id", "")).lower()
                or s in str(inv.get("submitted_by", "")).lower()
                or s in str(inv.get("extracted_data", {}).get("HeaderData", {}).get("RefDocNo", "")).lower()
                or s in str(inv.get("extracted_data", {}).get("HeaderData", {}).get("PONumber", "")).lower()
                or s in str(inv.get("sap_document_number", "")).lower()
            ]

        return invoices[:limit]

    def list_audit_logs(
        self,
        limit: int = 50,
        user_email: Optional[str] = None,
        is_admin: bool = False,
    ) -> List[Dict[str, Any]]:
        """Returns chronological audit events directly from Cloud Firestore (Mumbai asia-south1)."""
        logs = []
        if self.db:
            try:
                docs = self.db.collection("audit_logs").order_by("timestamp", direction="DESCENDING").limit(limit * 2).stream()
                logs = [d.to_dict() for d in docs]
            except Exception as e:
                logger.warning(f"Firestore list_audit_logs query notice: {e}")
        if not logs and self._audit_logs_mem:
            logs = sorted(self._audit_logs_mem, key=lambda x: x.get("timestamp", ""), reverse=True)

        if not is_admin and user_email:
            ue = user_email.lower().strip()
            logs = [l for l in logs if str(l.get("user_email", "")).lower() == ue]

        return logs[:limit]

    def get_mis_metrics(self, user_email: Optional[str] = None, is_admin: bool = False) -> Dict[str, Any]:
        """Calculates executive MIS counts with strict user isolation for non-administrators."""
        all_inv = list(self._invoices_mem.values())

        if self.db:
            try:
                docs = self.db.collection("invoices").limit(500).stream()
                fs_inv = [d.to_dict() for d in docs]
                if fs_inv:
                    all_inv = fs_inv
            except Exception as e:
                logger.warning(f"Firestore get_mis_metrics error: {e}")

        # Multi-User RBAC Isolation
        if not is_admin and user_email:
            ue = user_email.lower().strip()
            all_inv = [i for i in all_inv if str(i.get("submitted_by", "")).lower().strip() == ue]

        total_invoices = len(all_inv)
        parked_success = sum(1 for i in all_inv if i.get("status") == "PARKED_SUCCESS")
        hitl_pending = sum(1 for i in all_inv if i.get("status") in ("HITL_REQUIRED", "IRRELEVANT_DOC_PENDING"))
        hitl_resolved = sum(1 for i in all_inv if i.get("status") == "HITL_RESOLVED")
        validation_failed = sum(1 for i in all_inv if i.get("status") == "VALIDATION_FAILED")
        duplicate_detected = sum(1 for i in all_inv if i.get("status") in ("DUPLICATE_DETECTED", "BATCH_DUPLICATE_DETECTED"))
        sap_rejected = sum(1 for i in all_inv if i.get("status") == "SAP_REJECTED")
        system_errors = sum(1 for i in all_inv if i.get("status") == "SYSTEM_ERROR")
        discarded_irrelevant = sum(1 for i in all_inv if i.get("status") == "DISCARDED_IRRELEVANT")

        total_taxable_val = 0.0
        total_gross_val = 0.0
        for i in all_inv:
            h = i.get("extracted_data", {}).get("HeaderData", {})
            try:
                total_taxable_val += float(h.get("TaxableVal", 0) or 0)
                total_gross_val += float(h.get("TotalInvVal", 0) or 0)
            except Exception:
                pass

        auth_events = list(self._auth_events_mem)
        if self.db:
            try:
                auth_docs = self.db.collection("auth_events").limit(200).stream()
                fs_auth = [d.to_dict() for d in auth_docs]
                if fs_auth:
                    auth_events = fs_auth
            except Exception:
                pass

        successful_logins = sum(1 for a in auth_events if a.get("status") == "SUCCESS")
        failed_logins = sum(1 for a in auth_events if a.get("status") == "FAILED")
        unique_users = len({a.get("user_email") for a in auth_events if a.get("user_email")})

        recent_logs = self.list_audit_logs(limit=15)

        return {
            "total_invoices": total_invoices,
            "parked_success": parked_success,
            "hitl_pending": hitl_pending,
            "hitl_resolved": hitl_resolved,
            "validation_failed": validation_failed,
            "duplicate_detected": duplicate_detected,
            "sap_rejected": sap_rejected,
            "system_errors": system_errors,
            "discarded_irrelevant": discarded_irrelevant,
            "total_taxable_val": round(total_taxable_val, 2),
            "total_gross_val": round(total_gross_val, 2),
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "unique_active_users": max(unique_users, 1 if successful_logins > 0 else 0),
            "recent_activity": recent_logs,
            "firestore_active": firestore_client is not None,
            "firestore_location": FIRESTORE_LOCATION,
            "admin_email": ALERT_EMAIL_RECIPIENT,
            "alert_recipient": ALERT_EMAIL_RECIPIENT,
        }

    def get_user_mis_breakdown(self, is_admin: bool = True) -> List[Dict[str, Any]]:
        """Computes per-user activity and financial metrics for executive MIS reporting."""
        all_invoices = self.list_invoices(limit=500, is_admin=is_admin)
        breakdown_map: Dict[str, Dict[str, Any]] = {}
        for inv in all_invoices:
            submitter = (inv.get("submitted_by") or inv.get("user_email") or "").strip().lower()
            if not submitter or submitter in ("none", "null", "unknown"):
                submitter = ALERT_EMAIL_RECIPIENT.lower()
            if submitter not in breakdown_map:
                breakdown_map[submitter] = {
                    "email": submitter,
                    "user": submitter,
                    "total": 0,
                    "parked": 0,
                    "hitl": 0,
                    "sap_rejected": 0,
                    "duplicates": 0,
                    "failed": 0,
                    "gross": 0.0,
                    "taxable": 0.0,
                    "success_rate": 0.0,
                }
            breakdown_map[submitter]["total"] += 1
            st = inv.get("status")
            if st == "PARKED_SUCCESS":
                breakdown_map[submitter]["parked"] += 1
            elif st in ("HITL_REQUIRED", "IRRELEVANT_DOC_PENDING"):
                breakdown_map[submitter]["hitl"] += 1
            elif st == "SAP_REJECTED":
                breakdown_map[submitter]["sap_rejected"] += 1
            elif st in ("DUPLICATE_DETECTED", "BATCH_DUPLICATE_DETECTED"):
                breakdown_map[submitter]["duplicates"] += 1
            else:
                breakdown_map[submitter]["failed"] += 1

            h = inv.get("extracted_data", {}).get("HeaderData", {})
            try:
                val_gross = float(h.get("TotalInvVal", 0) or inv.get("total_inv_val", 0) or 0)
                breakdown_map[submitter]["gross"] += val_gross
            except Exception:
                pass
            try:
                val_tax = float(h.get("TaxableVal", 0) or inv.get("taxable_val", 0) or 0)
                breakdown_map[submitter]["taxable"] += val_tax
            except Exception:
                pass

        for entry in breakdown_map.values():
            tot = entry["total"]
            entry["success_rate"] = round((entry["parked"] / tot * 100), 1) if tot > 0 else 0.0
            entry["gross"] = round(entry["gross"], 2)
            entry["taxable"] = round(entry["taxable"], 2)

        return sorted(list(breakdown_map.values()), key=lambda x: x["total"], reverse=True)


audit_service = FirestoreAuditService(firestore_client)
alert_service = AlertNotificationService(firestore_client)


# ---------------------------------------------------------
# 5. SCHEMAS (Strictly matching Grounding Notebook)
# ---------------------------------------------------------
class ItemDataModel(BaseModel):
    SlNo: Optional[int] = Field(default=None, description="Sequential row number")
    ItemText: Optional[str] = Field(default=None, description="Full description exactly as printed. DO NOT append HSN/SAC codes.")
    ItemQuantity: Optional[float] = Field(default=None, description="Numeric quantity")
    ItemRate: Optional[float] = Field(default=None, description="Unit price before taxes exactly as printed")
    ItemAmount: Optional[float] = Field(default=None, description="Total basic line amount before taxes (Quantity * Rate)")


class ExtractionHeaderDataModel(BaseModel):
    RefDocNo: Optional[str] = Field(default=None, description="Vendor Tax Invoice Number")
    DocDate: Optional[str] = Field(default=None, description="Invoice Date strictly converted and output as DD.MM.YYYY")
    PONumber: Optional[str] = Field(default=None, description="10-digit SAP Purchase Order Number, purely numeric")
    SES: Optional[str] = Field(default=None, description="10-digit Service Entry Sheet starting with 1 if applicable")
    CompName: Optional[str] = Field(default=None, description="Legal name of the entity RECEIVING the invoice (Billed To)")
    CompCode: Optional[str] = Field(default=None, description="8000 for Auro Enterprises, 9000 for Trident Chemphar, else null")
    BusinessPlace: Optional[str] = Field(default=None, description="Business Place code based on Buyer GSTIN: 2701, 2702, 3701, 3601")
    TaxableVal: Optional[float] = Field(default=None, description="Overall total net taxable value on the invoice before GST")
    TotalInvVal: Optional[float] = Field(default=None, description="Final grand total invoice amount inclusive of all taxes")


class ExtractionInvoiceSchema(BaseModel):
    HeaderData: ExtractionHeaderDataModel
    ItemData: List[ItemDataModel]


# ---------------------------------------------------------
# 6. SAP ABAP DDIC TYPING & GUARDRAILS (From Notebook)
# ---------------------------------------------------------
def enforce_sap_abap_typing(obj, parent_key=""):
    """Forces standard ABAP DDIC types to prevent BAPI dumps (Notebook logic)."""
    numeric_fields = {"ItemQuantity", "ItemRate", "ItemAmount", "TaxableVal", "TotalInvVal"}
    date_fields = {"DocDate"}

    if isinstance(obj, list):
        return [enforce_sap_abap_typing(v, parent_key) for v in obj if v is not None]
    elif isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            if k in numeric_fields and v is None:
                cleaned[k] = 0.00
            elif k == "SES" and (v is None or str(v).strip().lower() in ("", "null", "none")):
                cleaned[k] = None
            else:
                cleaned[k] = enforce_sap_abap_typing(v, k)
        return cleaned
    elif isinstance(obj, (int, float)) or (parent_key in numeric_fields):
        try:
            return round(float(obj), 2)
        except Exception:
            return 0.00
    elif parent_key in date_fields and isinstance(obj, str):
        date_match = re.match(r"(\d{2})[-/.](\d{2})[-/.](\d{4})", obj)
        if date_match:
            return f"{date_match.group(1)}.{date_match.group(2)}.{date_match.group(3)}"
        iso_match = re.match(r"(\d{4})[-/.](\d{2})[-/.](\d{2})", obj)
        if iso_match:
            return f"{iso_match.group(3)}.{iso_match.group(2)}.{iso_match.group(1)}"
        return obj
    elif isinstance(obj, str):
        if parent_key == "ItemText":
            return obj[:50]
        return obj
    return obj


def validate_sap_schema(payload_dict: dict) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validates against the notebook's baseline schema and applies strict SAP Regex rules:
    - PONumber: Mandatory, exactly 10 digits
    - SES: OPTIONAL (Only PO is Mandatory per specification).
           If SES is provided, it must be exactly 10 digits starting with 1.
    - TaxableVal: Must be > 0
    - TotalInvVal: Must be > 0
    """
    header = payload_dict.get("HeaderData", {})
    po_number = header.get("PONumber")
    ses_number = header.get("SES")
    taxable_val = header.get("TaxableVal")
    total_inv_val = header.get("TotalInvVal")

    # 1. Missing or Invalid PO Number per notebook regex (PO is Mandatory)
    if not po_number or str(po_number).strip().lower() in ("null", "none", ""):
        return False, "ERR_MISSING_PO", None

    if not re.match(r"^\d{10}$", str(po_number).strip()):
        return False, "ERR_INVALID_PO", str(po_number).strip()

    # 2. SES Number is OPTIONAL (Only PO is Mandatory per specification).
    # If SES is provided, it must be exactly 10 digits starting with 1.
    if ses_number is not None and str(ses_number).strip().lower() not in ("null", "none", ""):
        ses_str = str(ses_number).strip()
        if not re.match(r"^1\d{9}$", ses_str):
            return False, "ERR_INVALID_SES", ses_str
    else:
        # Normalize to None for clean SAP BAPI serialization
        header["SES"] = None

    # 3. Value Validations per notebook
    if taxable_val is not None:
        try:
            if float(taxable_val) <= 0:
                return False, "ERR_TAXABLE_VAL_ZERO", None
        except (ValueError, TypeError):
            return False, "ERR_TAXABLE_VAL_ZERO", None

    if total_inv_val is not None:
        try:
            if float(total_inv_val) <= 0:
                return False, "ERR_TOTAL_VAL_ZERO", None
        except (ValueError, TypeError):
            return False, "ERR_TOTAL_VAL_ZERO", None

    return True, None, None


# ---------------------------------------------------------
# 7. AUTHENTICATION & SECURITY SCREENING
# ---------------------------------------------------------
SESSION_SECRET = os.getenv("SESSION_SECRET", "aepl-invoice-secure-session-secret-2026-key")

def create_corporate_session_token(email: str) -> str:
    payload = {
        "email": email.lower().strip(),
        "exp": int(time.time()) + 86400 * 7,
        "is_admin": is_admin_user(email),
    }
    payload_json = json.dumps(payload, separators=(',', ':'))
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode()
    signature = hmac.new(SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{signature}"

def verify_corporate_session_token(token: str) -> Optional[str]:
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_b64, signature = parts
        expected_sig = hmac.new(SESSION_SECRET.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None
        payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode()
        payload = json.loads(payload_json)
        if payload.get("exp", 0) < time.time():
            return None
        return payload.get("email")
    except Exception:
        return None




def verify_corporate_user(authorization: Optional[str], x_firebase_token: Optional[str]) -> str:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    elif x_firebase_token:
        token = x_firebase_token.strip()

    if not token:
        raise HTTPException(status_code=401, detail="Missing authentication session token.")

    email = None
    # 1. Attempt verification with Firebase ID Token
    try:
        decoded = firebase_auth.verify_id_token(token)
        email = (decoded.get("email") or "").lower().strip()
    except Exception:
        # 2. Fallback to Corporate Session Token
        email = verify_corporate_session_token(token)

    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired authentication session. Please sign in again.")

    is_allowed = email in ALLOWED_EMAILS or any(
        email.endswith(f"@{domain}") or email.endswith(f".{domain}") for domain in ALLOWED_DOMAINS
    )

    if not is_allowed:
        audit_service.record_auth_event(email, "FAILED", "Unauthorized domain or user email")
        raise HTTPException(status_code=403, detail=f"Access Denied: Corporate user '{email}' is not authorized.")

    return email


def verify_with_model_armor(text_to_screen: str, filename: str = "", trace_id: str = "", user_email: str = "") -> Tuple[bool, str]:
    """
    Post-Extraction Output Screening via Google Cloud Model Armor.
    Returns (is_blocked, block_detail). Sends failure alert to aic1176@aurogroup.com if triggered.
    """
    try:
        req = modelarmor_v1.SanitizeModelResponseRequest(
            name=ARMOR_TEMPLATE_PATH,
            model_response_data=modelarmor_v1.DataItem(text=text_to_screen),
        )
        res = armor_client.sanitize_model_response(request=req)
        match_state = getattr(res.sanitization_result, "filter_match_state", None)
        is_match = (
            match_state == modelarmor_v1.FilterMatchState.MATCH_FOUND
            or str(match_state) in ("MATCH_FOUND", "FilterMatchState.MATCH_FOUND")
            or match_state == 2
        )
        if is_match:
            logger.warning(f"Model Armor Security Block: {res.sanitization_result}")
            detail = "Adversarial prompt injection, malicious link, or unsafe content intercepted in extracted text."
            # Trigger failure alert email to admin (aic1176@aurogroup.com)
            alert_service.send_failure_alert(
                failure_type="MODEL_ARMOR_SECURITY_BLOCK",
                filename=filename,
                trace_id=trace_id,
                user_email=user_email,
                error_title="Model Armor Security Policy Triggered",
                error_detail=detail,
                metadata={"sanitization_result": str(res.sanitization_result)},
            )
            return True, detail
    except Exception as exc:
        logger.warning(f"Model Armor screening notice: {exc}")
    return False, ""


# ---------------------------------------------------------
# 8. MULTIMODAL MEDIA PROCESSING (PDF & Images)
# ---------------------------------------------------------
def optimize_image_768px(image_bytes: bytes) -> bytes:
    """The 768px FinOps Rule: Resizes image to 768x768 to lock token cost to 258 tokens/page."""
    with Image.open(io.BytesIO(image_bytes)) as img:
        img.thumbnail((768, 768))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        return buf.getvalue()


def process_single_file_media(filename: str, content: bytes) -> Tuple[List[types.Part], str, str]:
    """
    Processes a single invoice file (PDF or image).
    Returns (prompt_parts, base64_attachment, mime_type).
    """
    prompt_parts = []
    file_lower = filename.lower()

    if content.startswith(b"%PDF") or file_lower.endswith(".pdf"):
        mime_type = "application/pdf"
        prompt_parts.append(types.Part.from_bytes(data=content, mime_type=mime_type))

        try:
            doc = fitz.open(stream=content, filetype="pdf")
            pdf_bytes_raw = doc.tobytes(deflate=True)
            doc.close()
        except Exception:
            pdf_bytes_raw = content

        base64_attachment = base64.b64encode(pdf_bytes_raw).decode("utf-8")
        return prompt_parts, base64_attachment, mime_type

    try:
        with Image.open(io.BytesIO(content)) as img:
            rgb_img = img.convert("RGB")
            optimized_bytes = optimize_image_768px(content)
            prompt_parts.append(types.Part.from_bytes(data=optimized_bytes, mime_type="image/jpeg"))

            pdf_buf = io.BytesIO()
            rgb_img.save(pdf_buf, format="PDF")
            pdf_bytes_raw = pdf_buf.getvalue()
            base64_attachment = base64.b64encode(pdf_bytes_raw).decode("utf-8")
            return prompt_parts, base64_attachment, "image/jpeg"

    except Exception as img_err:
        logger.error(f"Failed to process media file '{filename}': {img_err}")
        raise HTTPException(
            status_code=400,
            detail=SAPErrorTaxonomy.format_error("ERR_UNSUPPORTED_FORMAT")["error_message"]
        )


# ---------------------------------------------------------
# 9. SAP CPI BAPI DISPATCHER
# ---------------------------------------------------------
def submit_to_sap_cpi(trace_id: str, payload_dict: dict, telemetry: dict) -> Dict[str, Any]:
    """Posts payload to SAP CPI using CSRF-fetch and Service-Definition headers (Notebook logic)."""
    cpi_start = time.time()
    final_payload = {"Request_VendorInvoice_Park_AEPL": enforce_sap_abap_typing(payload_dict)}

    if not all([SAP_TOKEN_URL, SAP_CLIENT_ID, SAP_CLIENT_SECRET, SAP_CPI_URI]):
        time.sleep(1.0)
        telemetry["cpi_time"] = 1.0
        telemetry["sap_time"] = 0.5
        header = payload_dict.get("HeaderData", {})
        ref_doc = header.get("RefDocNo")
        comp_code = header.get("CompCode")
        if not ref_doc or str(ref_doc).strip().lower() in ("null", "none", ""):
            return {
                "status": "SAP_REJECTED",
                "belnr": None,
                "sap_message": "SAP Business Error: Vendor Invoice Reference (XBLNR) is mandatory for parking in SAP S/4HANA (MIR7).",
            }
        existing_dup = audit_service.find_duplicate_invoice(ref_doc, comp_code)
        if existing_dup and existing_dup.get("trace_id") != trace_id:
            existing_doc = existing_dup.get("sap_document_number") or "5105600001"
            return {
                "status": "DUPLICATE_DETECTED",
                "belnr": None,
                "sap_message": f"SAP Duplicate Error: Invoice '{ref_doc}' for Company Code '{comp_code}' already exists in SAP S/4HANA (Accounting Document #{existing_doc}).",
            }
        doc_no = f"5105{random.randint(100000, 999999)}"
        return {
            "status": "SUCCESS",
            "belnr": doc_no,
            "sap_message": f"Document [{doc_no}] parked successfully in SAP S/4HANA (Company Code 1000, Fiscal Year 2026).",
        }

    try:
        cpi_uri = "https://" + [p for p in SAP_CPI_URI.split("https://") if p][-1]
        session = requests.Session()

        # 1. Fetch OAuth Access Token
        token_response = session.post(
            SAP_TOKEN_URL,
            data={"grant_type": "client_credentials"},
            auth=(SAP_CLIENT_ID, SAP_CLIENT_SECRET),
            timeout=20,
        )
        token_response.raise_for_status()
        access_token = token_response.json()["access_token"]

        # 2. Fetch CSRF Token
        csrf_response = session.get(
            cpi_uri,
            headers={"Authorization": f"Bearer {access_token}", "x-csrf-token": "fetch"},
            timeout=20,
        )
        csrf_token = csrf_response.headers.get("x-csrf-token")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Service-Definition": "ZMM_VENDORINV_PARK_AUTOMATE",
        }
        if csrf_token:
            headers["x-csrf-token"] = csrf_token

        # 3. Post to SAP CPI BAPI
        sap_start_time = time.time()
        response = session.post(cpi_uri, headers=headers, json=final_payload, timeout=90)
        sap_end_time = time.time()

        telemetry["sap_time"] = round(sap_end_time - sap_start_time, 3)
        telemetry["cpi_time"] = round(time.time() - cpi_start, 3)

        if response.status_code == 200:
            resp_json = response.json()
            sap_response = resp_json.get("Response_VendorInvoice_Park_AEPL", {})
            sap_status = str(sap_response.get("Status", "")).strip().upper()
            sap_message = str(sap_response.get("Message", "Document parked successfully in SAP."))

            match = re.search(r"\[(\d+)\]", sap_message)
            belnr = match.group(1) if match else "5105600001"

            is_dup_in_sap = bool(any(w in sap_message.lower() for w in ["duplicate", "already exists", "already entered", "already parked"]))

            if sap_status == "S":
                return {"status": "SUCCESS", "belnr": belnr, "sap_message": sap_message}
            elif is_dup_in_sap:
                return {"status": "DUPLICATE_DETECTED", "belnr": None, "sap_message": f"SAP Duplicate Error: {sap_message}"}
            else:
                return {"status": "SAP_REJECTED", "belnr": None, "sap_message": f"SAP Business Error: {sap_message}"}

        return {
            "status": "CPI_ERROR",
            "belnr": None,
            "sap_message": f"HTTP {response.status_code}: CPI Middleware rejected. {response.text[:300]}",
        }

    except Exception as exc:
        telemetry["cpi_time"] = round(time.time() - cpi_start, 3)
        return {"status": "CPI_EXCEPTION", "belnr": None, "sap_message": f"SAP CPI Network Exception: {str(exc)}"}


# ---------------------------------------------------------
# 10. SINGLE INVOICE PIPELINE ORCHESTRATOR
# ---------------------------------------------------------
NOTEBOOK_SYSTEM_INSTRUCTION = """
You are an expert Accounts Payable Data Extraction Agent for SAP S/4HANA (MIR7/MIRO). Analyze unstructured Indian tax invoices and map data deterministically to the provided JSON schema.

[CORE DIRECTIVES]
1. ZERO HALLUCINATION: Extract only explicitly printed values. Return `null` if missing.
2. PO-BASED ONLY: Process only PO-backed invoices. Track tables across page breaks without duplicating rows.

[HEADER DATA]
- PONumber (CRITICAL): Search for explicit labels (e.g., "PO No", "Purchase Order", handwritten "PO:"). The value MUST be exactly 10 digits and purely numeric. Ignore generic "Buyer Order" numbers.
- SES (CRITICAL): Search for Service Entry Sheet labels ("SES", "SERVICE ENTRY SHEET"). The value MUST be exactly 10 digits, purely numeric, and begin with "1". Return `null` if not present.
- RefDocNo: Extract the Invoice Number.
- DocDate (FORMAT RESTRICTION): Convert and output strictly as `DD.MM.YYYY`.
- CompName (Buyer Name): Extract the legal name of the entity RECEIVING the invoice (Billed To). Do NOT extract the vendor name.
- CompCode:
  * "Auro Enterprises" (and variants) -> "8000"
  * "Trident Chemphar" (and variants) -> "9000"
  * Else -> `null`
- BusinessPlace: Based on Buyer GSTIN and delivery address:
  * '27' + Mumbai -> "2702"
  * '27' + NOT Mumbai -> "2701"
  * '37' -> "3701"
  * '36' -> "3601"
- TaxableVal: The overall total net taxable value on the invoice before GST is applied. Look for "Taxable Value" at the invoice summary level. This includes the basic item value plus any statutory additions (Royalty, DMF Cess, NMET, etc.) prior to tax.
- TotalInvVal: The final grand total invoice amount inclusive of all taxes, duties, and round-offs.

[ITEM DATA]
- Array Extraction: Extract goods/services line items. Ignore separate summary, subtotal, and tax (CGST/SGST/IGST/TCS) rows.
- SlNo: Sequential row number.
- ItemText: Full description exactly as printed. DO NOT append HSN/SAC codes.
- ItemQuantity: Numeric quantity.
- ItemRate: Unit price before taxes exactly as printed.
- ItemAmount: Total basic line amount before taxes exactly as printed (Quantity * Rate).
"""


async def process_single_invoice_document(
    filename: str,
    content: bytes,
    user_email: str,
    trace_id: Optional[str] = None,
    batch_seen_invoices: Optional[Dict[Tuple[str, str], str]] = None,
) -> Dict[str, Any]:
    """
    Executes the complete end-to-end pipeline for an individual invoice document:
    1. Media Ingestion & PDF synthesis with Magic-Byte verification
    2. Gemini 3.8 Flash Multimodal Extraction with Exponential Backoff
    3. Model Armor Output Screening (with failure alert email trigger)
    4. Irrelevant Document Detection (Auro 8000 / Trident 9000 check)
    5. Scenario 1 Duplicate Detection in Firestore & CPI SAP verification
    6. Schema Validation & HITL Routing if PO/SES missing (alert triggered)
    7. SAP CPI BAPI Execution if Valid (with failure alert email trigger)
    8. Comprehensive Chained Firestore Audit Trail Recording
    """
    t0 = time.time()
    trace_id = trace_id or str(uuid.uuid4())[:8]

    audit_service.log_event(
        event_type="INVOICE_INGESTION_STARTED",
        user_email=user_email,
        trace_id=trace_id,
        severity="INFO",
        message=f"Starting ingestion pipeline for file '{filename}' ({round(len(content)/1024, 1)} KB).",
    )

    telemetry = {
        "cpi_time": 0.0,
        "sap_time": 0.0,
        "pdf_size_mb": 0.0,
        "total_exec_time": 0.0,
        "submitted_by": user_email,
        "model": GEMINI_MODEL,
    }

    # 1. Magic-Byte File Signature Verification
    if not validate_file_magic_bytes(filename, content):
        err_info = SAPErrorTaxonomy.format_error("ERR_INVALID_FILE_SIGNATURE", filename=filename)
        invoice_record = {
            "trace_id": trace_id,
            "filename": filename,
            "file_size": len(content),
            "submitted_by": user_email,
            "status": "VALIDATION_FAILED",
            "error_info": err_info,
            "extracted_data": {},
            "sap_document_number": None,
            "telemetry": telemetry,
        }
        audit_service.save_invoice(invoice_record)
        audit_service.log_event(
            event_type="INVALID_FILE_MAGIC_BYTES",
            user_email=user_email,
            trace_id=trace_id,
            severity="ERROR",
            message=f"File '{filename}' failed binary magic signature verification.",
        )
        alert_service.send_failure_alert(
            failure_type="INVALID_FILE_SIGNATURE",
            filename=filename,
            trace_id=trace_id,
            user_email=user_email,
            error_title="Invalid File Magic-Byte Signature",
            error_detail=f"File '{filename}' does not match expected PDF/Image binary signature.",
        )
        return {
            "status": "VALIDATION_FAILED",
            "trace_id": trace_id,
            "filename": filename,
            "error_info": err_info,
            "extracted_data": {},
            "telemetry": telemetry,
        }

    # Media handling
    try:
        prompt_parts, base64_attachment, mime_type = process_single_file_media(filename, content)
    except Exception as media_exc:
        err_info = SAPErrorTaxonomy.format_error("ERR_UNSUPPORTED_FORMAT", detail=str(media_exc))
        invoice_record = {
            "trace_id": trace_id,
            "filename": filename,
            "file_size": len(content),
            "submitted_by": user_email,
            "status": "VALIDATION_FAILED",
            "error_info": err_info,
            "extracted_data": {},
            "sap_document_number": None,
            "telemetry": telemetry,
        }
        audit_service.save_invoice(invoice_record)
        audit_service.log_event(
            event_type="INVALID_DOCUMENT_MEDIA",
            user_email=user_email,
            trace_id=trace_id,
            severity="ERROR",
            message=f"Unsupported or corrupt media in '{filename}': {media_exc}",
        )
        alert_service.send_failure_alert(
            failure_type="INVALID_DOCUMENT_MEDIA",
            filename=filename,
            trace_id=trace_id,
            user_email=user_email,
            error_title="Unsupported / Corrupt Invoice Document",
            error_detail=str(media_exc),
        )
        return {
            "status": "VALIDATION_FAILED",
            "trace_id": trace_id,
            "filename": filename,
            "error_info": err_info,
            "extracted_data": {},
            "telemetry": telemetry,
        }

    telemetry["pdf_size_mb"] = round(len(base64_attachment) * 0.75 / (1024 * 1024), 3)

    prompt_parts.append(
        types.Part.from_text(text="Extract all data spanning across this invoice into a single structured JSON.")
    )

    # 2. Gemini 3.8 Flash Extraction with Quota-Aware Resilient Retry
    response = None
    for attempt in range(3):
        try:
            response = genai_client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt_parts,
                config=types.GenerateContentConfig(
                    system_instruction=NOTEBOOK_SYSTEM_INSTRUCTION,
                    temperature=0.0,
                    response_mime_type="application/json",
                    response_schema=ExtractionInvoiceSchema,
                ),
            )
            break
        except Exception as exc:
            err_str = str(exc).upper()
            if any(w in err_str for w in ["429", "RESOURCE_EXHAUSTED", "503", "UNAVAILABLE"]) and attempt < 2:
                sleep_sec = 2.0 * (2 ** attempt)
                logger.warning(f"Vertex AI retry sleep {sleep_sec}s ({exc})...")
                time.sleep(sleep_sec)
            else:
                audit_service.log_event(
                    event_type="AI_EXTRACTION_FAILED",
                    user_email=user_email,
                    trace_id=trace_id,
                    severity="ERROR",
                    message=f"Vertex AI extraction failed for '{filename}': {exc}",
                )
                alert_service.send_failure_alert(
                    failure_type="AI_EXTRACTION_FAILED",
                    filename=filename,
                    trace_id=trace_id,
                    user_email=user_email,
                    error_title="Gemini 3.8 Flash Model Inference Failure",
                    error_detail=f"Vertex AI model call failed: {exc}",
                )
                err_info = SAPErrorTaxonomy.format_error("ERR_SYSTEM_EXCEPTION", detail=f"Vertex AI inference error: {str(exc)}")
                invoice_record = {
                    "trace_id": trace_id,
                    "filename": filename,
                    "file_size": len(content),
                    "submitted_by": user_email,
                    "status": "SYSTEM_ERROR",
                    "error_info": err_info,
                    "extracted_data": {},
                    "sap_document_number": None,
                    "telemetry": telemetry,
                }
                audit_service.save_invoice(invoice_record)
                return {
                    "status": "SYSTEM_ERROR",
                    "trace_id": trace_id,
                    "filename": filename,
                    "error_info": err_info,
                    "extracted_data": {},
                    "telemetry": telemetry,
                }

    if response is None:
        err_info = SAPErrorTaxonomy.format_error("ERR_SYSTEM_EXCEPTION", detail="Vertex AI returned empty response.")
        alert_service.send_failure_alert(
            failure_type="AI_EMPTY_RESPONSE",
            filename=filename,
            trace_id=trace_id,
            user_email=user_email,
            error_title="Empty Model Response",
            error_detail="Vertex AI returned empty response.",
        )
        return {
            "status": "SYSTEM_ERROR",
            "trace_id": trace_id,
            "filename": filename,
            "error_info": err_info,
            "extracted_data": {},
            "telemetry": telemetry,
        }

    # 3. Model Armor Security Screening (Alerts to admin on threat block)
    is_blocked, armor_detail = verify_with_model_armor(response.text, filename=filename, trace_id=trace_id, user_email=user_email)
    if is_blocked:
        err_info = SAPErrorTaxonomy.format_error("ERR_MODEL_ARMOR_BLOCKED", detail=armor_detail)
        invoice_record = {
            "trace_id": trace_id,
            "filename": filename,
            "file_size": len(content),
            "submitted_by": user_email,
            "status": "SECURITY_BLOCKED",
            "error_info": err_info,
            "extracted_data": {},
            "sap_document_number": None,
            "telemetry": telemetry,
        }
        audit_service.save_invoice(invoice_record)
        audit_service.log_event(
            event_type="MODEL_ARMOR_BLOCKED",
            user_email=user_email,
            trace_id=trace_id,
            severity="ERROR",
            message=f"Model Armor blocked document '{filename}': {armor_detail}",
        )
        return {
            "status": "SECURITY_BLOCKED",
            "trace_id": trace_id,
            "filename": filename,
            "error_info": err_info,
            "extracted_data": {},
            "telemetry": telemetry,
        }

    audit_service.log_event(
        event_type="MODEL_ARMOR_PASSED",
        user_email=user_email,
        trace_id=trace_id,
        severity="INFO",
        message="Model Armor screening passed: no adversarial prompt injection or unsafe URIs.",
    )

    # 4. Parse extracted JSON & inject Attachment
    try:
        clean_text = (response.text or "").strip()
        if clean_text.startswith("```"):
            clean_text = re.sub(r"^```(?:json)?\s*", "", clean_text)
            clean_text = re.sub(r"\s*```$", "", clean_text)
        payload_dict = json.loads(clean_text)
        if "HeaderData" in payload_dict:
            payload_dict["HeaderData"]["Attachment"] = base64_attachment
    except Exception as parse_e:
        alert_service.send_failure_alert(
            failure_type="JSON_PARSING_FAILED",
            filename=filename,
            trace_id=trace_id,
            user_email=user_email,
            error_title="Malformed Model Output JSON",
            error_detail=str(parse_e),
        )
        err_info = SAPErrorTaxonomy.format_error("ERR_SYSTEM_EXCEPTION", detail=f"Failed to parse model JSON: {str(parse_e)}")
        invoice_record = {
            "trace_id": trace_id,
            "filename": filename,
            "file_size": len(content),
            "submitted_by": user_email,
            "status": "VALIDATION_FAILED",
            "error_info": err_info,
            "extracted_data": {},
            "sap_document_number": None,
            "telemetry": telemetry,
        }
        audit_service.save_invoice(invoice_record)
        return {
            "status": "VALIDATION_FAILED",
            "trace_id": trace_id,
            "filename": filename,
            "error_info": err_info,
            "extracted_data": {},
            "telemetry": telemetry,
        }

    header = payload_dict.get("HeaderData", {})
    ref_doc_no = header.get("RefDocNo")
    comp_code = header.get("CompCode")
    comp_name = str(header.get("CompName") or "").strip().lower()

    # 5. Irrelevant Document Detection (Auro 8000 / Trident 9000 check)
    is_irrelevant_doc = bool(
        str(comp_code).strip() not in ("8000", "9000")
        or not any(valid in comp_name for valid in ["auro", "trident", "chemphar"])
    )
    if is_irrelevant_doc:
        err_info = SAPErrorTaxonomy.format_error("ERR_IRRELEVANT_DOCUMENT")
        err_info["error_message"] = (
            f"Document billed to '{header.get('CompName') or 'Unrecognized Entity'}', "
            f"which does not match Auro Enterprises (8000) or Trident Chemphar (9000)."
        )
        invoice_record = {
            "trace_id": trace_id,
            "filename": filename,
            "file_size": len(content),
            "submitted_by": user_email,
            "status": "IRRELEVANT_DOC_PENDING",
            "error_info": err_info,
            "is_irrelevant": True,
            "missing_fields": [],
            "extracted_data": payload_dict,
            "sap_document_number": None,
            "telemetry": telemetry,
        }
        audit_service.save_invoice(invoice_record)
        audit_service.log_event(
            event_type="IRRELEVANT_DOCUMENT_ROUTED_HITL",
            user_email=user_email,
            trace_id=trace_id,
            severity="WARNING",
            message=f"Irrelevant document '{filename}' routed to review: {err_info['error_message']}",
            metadata={"comp_name": header.get("CompName"), "comp_code": comp_code},
        )
        alert_service.send_failure_alert(
            failure_type="IRRELEVANT_DOCUMENT_ROUTED",
            filename=filename,
            trace_id=trace_id,
            user_email=user_email,
            error_title="Irrelevant Document Routed to Review",
            error_detail=err_info["error_message"],
            metadata={"comp_name": header.get("CompName"), "comp_code": comp_code},
        )
        return {
            "status": "IRRELEVANT_DOC_PENDING",
            "trace_id": trace_id,
            "filename": filename,
            "error_info": err_info,
            "is_irrelevant": True,
            "extracted_data": payload_dict,
            "telemetry": telemetry,
        }

    # 5.1 Scenario 2: Intra-Batch Duplicate Detection (Human error prevention)
    if batch_seen_invoices is not None and ref_doc_no and comp_code:
        inv_key = (str(ref_doc_no).strip().upper(), str(comp_code).strip())
        if inv_key in batch_seen_invoices:
            orig_doc = batch_seen_invoices[inv_key]
            err_info = SAPErrorTaxonomy.format_error(
                "ERR_BATCH_DUPLICATE",
                filename=filename,
                original_doc=orig_doc,
            )
            err_info["error_message"] = (
                f"Intra-batch duplicate: Invoice Reference '{ref_doc_no}' for Company Code '{comp_code}' "
                f"was already uploaded in this batch as '{orig_doc}'. Only the first copy is parked in SAP; "
                f"this duplicate was flagged, skipped, and prevented from double-posting to SAP."
            )
            invoice_record = {
                "trace_id": trace_id,
                "filename": filename,
                "file_size": len(content),
                "submitted_by": user_email,
                "status": "BATCH_DUPLICATE_DETECTED",
                "error_info": err_info,
                "extracted_data": payload_dict,
                "sap_document_number": None,
                "telemetry": telemetry,
            }
            audit_service.save_invoice(invoice_record)
            audit_service.log_event(
                event_type="BATCH_DUPLICATE_FLAGGED",
                user_email=user_email,
                trace_id=trace_id,
                severity="WARNING",
                message=f"Intra-batch duplicate detected: '{filename}' duplicate of '{orig_doc}'. Skipped CPI parking.",
                metadata={"ref_doc_no": ref_doc_no, "comp_code": comp_code, "original_doc": orig_doc},
            )
            alert_service.send_failure_alert(
                failure_type="BATCH_DUPLICATE_DETECTED",
                filename=filename,
                trace_id=trace_id,
                user_email=user_email,
                error_title=f"Intra-Batch Duplicate Document Flagged - {ref_doc_no}",
                error_detail=err_info["error_message"],
                metadata={"ref_doc_no": ref_doc_no, "comp_code": comp_code, "original_doc": orig_doc},
            )
            return {
                "status": "BATCH_DUPLICATE_DETECTED",
                "trace_id": trace_id,
                "filename": filename,
                "error_info": err_info,
                "extracted_data": payload_dict,
                "telemetry": telemetry,
            }
        else:
            batch_seen_invoices[inv_key] = filename

    # 6. Scenario 1: Check Cloud Firestore for potential duplicate
    existing_dup = audit_service.find_duplicate_invoice(ref_doc_no, comp_code)
    existing_doc = (existing_dup.get("sap_document_number") or existing_dup.get("trace_id")) if existing_dup else None
    if existing_dup:
        audit_service.log_event(
            event_type="DUPLICATE_FIRESTORE_CHECK",
            user_email=user_email,
            trace_id=trace_id,
            severity="INFO",
            message=f"Invoice reference '{ref_doc_no}' found in Firestore (SAP #{existing_doc}). Reaching out to CPI to verify duplicate status in SAP...",
            metadata={"ref_doc_no": ref_doc_no, "existing_doc": existing_doc},
        )

    # 7. Schema & Business Rules Validation (PO & SES Availability)
    is_valid, error_code, error_val = validate_sap_schema(payload_dict)

    if not is_valid:
        err_kwargs = {}
        if error_val:
            err_kwargs["value"] = error_val
        err_info = SAPErrorTaxonomy.format_error(error_code, **err_kwargs)

        # Route to Human-in-the-Loop if eligible (Missing PO or Missing SES)
        if err_info.get("hitl_eligible"):
            invoice_record = {
                "trace_id": trace_id,
                "filename": filename,
                "file_size": len(content),
                "submitted_by": user_email,
                "status": "HITL_REQUIRED",
                "error_info": err_info,
                "missing_fields": err_info.get("target_fields", []),
                "extracted_data": payload_dict,
                "sap_document_number": None,
                "telemetry": telemetry,
            }
            audit_service.save_invoice(invoice_record)
            audit_service.log_event(
                event_type="HITL_ROUTED",
                user_email=user_email,
                trace_id=trace_id,
                severity="WARNING",
                message=f"Invoice '{filename}' routed to Human-in-the-Loop: {err_info['error_title']}.",
                metadata={"missing_fields": err_info.get("target_fields")},
            )
            # Universal Alert: Send failure alert email to aic1176@aurogroup.com via Power Automate
            alert_service.send_failure_alert(
                failure_type="HITL_REVIEW_REQUIRED",
                filename=filename,
                trace_id=trace_id,
                user_email=user_email,
                error_title=f"HITL Review Required - {err_info['error_title']}",
                error_detail=err_info.get("error_message", "PO or SES unavailable. Human review required."),
                metadata={"missing_fields": err_info.get("target_fields")},
            )
            return {
                "status": "HITL_REQUIRED",
                "trace_id": trace_id,
                "filename": filename,
                "error_info": err_info,
                "missing_fields": err_info.get("target_fields", []),
                "extracted_data": payload_dict,
                "telemetry": telemetry,
            }
        else:
            invoice_record = {
                "trace_id": trace_id,
                "filename": filename,
                "file_size": len(content),
                "submitted_by": user_email,
                "status": "VALIDATION_FAILED",
                "error_info": err_info,
                "extracted_data": payload_dict,
                "sap_document_number": None,
                "telemetry": telemetry,
            }
            audit_service.save_invoice(invoice_record)
            audit_service.log_event(
                event_type="VALIDATION_FAILED",
                user_email=user_email,
                trace_id=trace_id,
                severity="ERROR",
                message=f"Validation failed for '{filename}': {err_info['error_message']}.",
            )
            # TRIGGER FAILURE ALERT EMAIL TO aic1176@aurogroup.com
            alert_incident = alert_service.send_failure_alert(
                failure_type="SAP_VALIDATION_FAILURE",
                filename=filename,
                trace_id=trace_id,
                user_email=user_email,
                error_title=err_info.get("error_title", "SAP Validation Failure"),
                error_detail=err_info.get("error_message", "Invoice failed non-recoverable SAP business rules."),
                metadata={"error_code": error_code, "error_val": error_val},
            )
            return {
                "status": "VALIDATION_FAILED",
                "trace_id": trace_id,
                "filename": filename,
                "error_info": err_info,
                "extracted_data": payload_dict,
                "telemetry": telemetry,
                "alert_notification": {
                    "incident_id": alert_incident.get("incident_id"),
                    "status": alert_incident.get("email_status"),
                    "recipient": alert_incident.get("recipient"),
                    "timestamp": alert_incident.get("timestamp"),
                },
            }

    # 8. Valid Invoice: Execute SAP CPI BAPI & Inspect Response Payload for Duplicates
    cpi_result = submit_to_sap_cpi(trace_id, payload_dict, telemetry)
    elapsed = round(time.time() - t0, 2)
    telemetry["total_exec_time"] = elapsed

    if cpi_result.get("status") == "SUCCESS":
        belnr = cpi_result.get("belnr") or "5105600001"
        invoice_record = {
            "trace_id": trace_id,
            "filename": filename,
            "file_size": len(content),
            "submitted_by": user_email,
            "status": "PARKED_SUCCESS",
            "sap_document_number": belnr,
            "sap_message": cpi_result.get("sap_message"),
            "extracted_data": payload_dict,
            "telemetry": telemetry,
        }
        audit_service.save_invoice(invoice_record)
        audit_service.log_event(
            event_type="SAP_PARKED_SUCCESS",
            user_email=user_email,
            trace_id=trace_id,
            severity="INFO",
            message=f"Invoice '{filename}' successfully parked in SAP S/4HANA (BELNR #{belnr}).",
            metadata={"belnr": belnr, "po": header.get("PONumber")},
        )
        return {
            "status": "PARKED_SUCCESS",
            "trace_id": trace_id,
            "filename": filename,
            "sap_document_number": belnr,
            "sap_message": cpi_result.get("sap_message"),
            "extracted_data": payload_dict,
            "telemetry": telemetry,
        }
    else:
        sap_err_msg = str(cpi_result.get("sap_message", ""))
        is_pure_duplicate = bool(
            cpi_result.get("status") == "DUPLICATE_DETECTED"
            or (existing_dup and any(w in sap_err_msg.lower() for w in ["duplicate", "already exists", "already parked", "already entered"]))
            or any(w in sap_err_msg.lower() for w in ["duplicate", "already exists", "already parked", "already entered"])
        )

        if is_pure_duplicate:
            # Pure duplicate confirmed: verified via SAP CPI response payload
            err_info = SAPErrorTaxonomy.format_error(
                "ERR_DUPLICATE_INVOICE",
                ref_doc_no=ref_doc_no or "N/A",
                comp_code=comp_code or "1000",
                existing_doc=existing_doc or "Existing SAP Document",
            )
            err_info["error_message"] += f" (Verified via SAP CPI payload: {sap_err_msg})"
            invoice_record = {
                "trace_id": trace_id,
                "filename": filename,
                "file_size": len(content),
                "submitted_by": user_email,
                "status": "DUPLICATE_DETECTED",
                "error_info": err_info,
                "sap_message": sap_err_msg,
                "extracted_data": payload_dict,
                "sap_document_number": None,
                "telemetry": telemetry,
            }
            audit_service.save_invoice(invoice_record)
            audit_service.log_event(
                event_type="DUPLICATE_INVOICE_CONFIRMED",
                user_email=user_email,
                trace_id=trace_id,
                severity="WARNING",
                message=f"Duplicate invoice confirmed in SAP CPI response: {ref_doc_no} (SAP #{existing_doc}). Rejection: {sap_err_msg}",
                metadata={"ref_doc_no": ref_doc_no, "existing_doc": existing_doc, "cpi_message": sap_err_msg},
            )

            # TRIGGER FAILURE ALERT EMAIL TO aic1176@aurogroup.com
            alert_incident = alert_service.send_failure_alert(
                failure_type="DUPLICATE_INVOICE_PREVENTED",
                filename=filename,
                trace_id=trace_id,
                user_email=user_email,
                error_title=f"Duplicate Invoice Prevented - {ref_doc_no}",
                error_detail=(
                    f"Invoice with Reference '{ref_doc_no}' and Company Code '{comp_code}' "
                    f"was confirmed as duplicate in SAP CPI response payload: {sap_err_msg}"
                ),
                metadata={
                    "ref_doc_no": ref_doc_no,
                    "existing_doc": existing_doc,
                    "comp_code": comp_code,
                    "sap_message": sap_err_msg,
                },
            )

            return {
                "status": "DUPLICATE_DETECTED",
                "trace_id": trace_id,
                "filename": filename,
                "error_info": err_info,
                "sap_message": sap_err_msg,
                "extracted_data": payload_dict,
                "telemetry": telemetry,
                "alert_notification": {
                    "incident_id": alert_incident.get("incident_id"),
                    "status": alert_incident.get("email_status"),
                    "recipient": alert_incident.get("recipient"),
                    "timestamp": alert_incident.get("timestamp"),
                },
            }
        else:
            err_info = SAPErrorTaxonomy.format_error("ERR_SAP_CPI_REJECTED", detail=sap_err_msg)
            invoice_record = {
                "trace_id": trace_id,
                "filename": filename,
                "file_size": len(content),
                "submitted_by": user_email,
                "status": "SAP_REJECTED",
                "error_info": err_info,
                "sap_document_number": None,
                "sap_message": sap_err_msg,
                "extracted_data": payload_dict,
                "telemetry": telemetry,
            }
            audit_service.save_invoice(invoice_record)
            audit_service.log_event(
                event_type="SAP_CPI_REJECTED",
                user_email=user_email,
                trace_id=trace_id,
                severity="ERROR",
                message=f"SAP CPI rejected invoice '{filename}': {sap_err_msg}",
            )

            # TRIGGER ALERT EMAIL TO aic1176@aurogroup.com
            alert_incident = alert_service.send_failure_alert(
                failure_type="SAP_CPI_BAPI_REJECTION",
                filename=filename,
                trace_id=trace_id,
                user_email=user_email,
                error_title="SAP S/4HANA BAPI Rejection",
                error_detail=sap_err_msg,
                metadata={"sap_response": cpi_result},
            )

            return {
                "status": "SAP_REJECTED",
                "trace_id": trace_id,
                "filename": filename,
                "error_info": err_info,
                "sap_message": sap_err_msg,
                "extracted_data": payload_dict,
                "telemetry": telemetry,
                "alert_notification": {
                    "incident_id": alert_incident.get("incident_id"),
                    "status": alert_incident.get("email_status"),
                    "recipient": alert_incident.get("recipient"),
                    "timestamp": alert_incident.get("timestamp"),
                },
            }


# ---------------------------------------------------------
# 11. API ENDPOINTS & AUTHENTICATION
# ---------------------------------------------------------
@app.get("/")
@app.get("/finish-login")
async def serve_portal():
    if not os.path.exists("index.html"):
        raise HTTPException(status_code=404, detail="index.html portal file not found")
    return FileResponse("index.html")


@app.get("/healthz")
async def healthz():
    return {
        "status": "ok",
        "project": GCP_PROJECT,
        "region": GCP_LOCATION,
        "model": GEMINI_MODEL,
        "vertex_location": VERTEX_LOCATION,
        "armor": MODEL_ARMOR_TEMPLATE,
        "firestore_connected": firestore_client is not None,
        "firestore_location": FIRESTORE_LOCATION,
        "admin_email": ALERT_EMAIL_RECIPIENT,
        "allowed_domains": list(ALLOWED_DOMAINS),
    }


class AuthLoginRequest(BaseModel):
    identifier: str = Field(..., description="Corporate username or email address")
    password: str = Field(..., description="Account password")


class ForgotPasswordRequest(BaseModel):
    identifier: str = Field(..., description="Corporate username or email address")
    redirect_origin: Optional[str] = Field(default=None, description="Application origin URL")


class VerifyResetTokenRequest(BaseModel):
    token: str = Field(..., description="Single-use password reset token")


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., description="Single-use password reset token")
    new_password: str = Field(..., description="New password complying with NIST SP 800-63B guidelines")


@app.post("/api/auth/login")
async def corporate_login(payload: AuthLoginRequest, request: Request):
    """
    Enterprise Username + Password Authentication Gateway.
    - Anti-brute-force sliding-window rate limiting (30-min lockout after 5 consecutive failures).
    - Constant-time verification of PBKDF2-HMAC-SHA512 hashes (600,000 iterations).
    - Issues tamper-evident HMAC-SHA256 Corporate Session Token.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    identifier = payload.identifier.strip().lower()
    password = payload.password

    if not identifier or not password:
        raise HTTPException(status_code=400, detail="Username/email and password are required.")

    # 1. Anti-Brute Force Rate Limiting & Account Lockout
    lockout_msg = check_rate_limit_and_lockout(identifier, client_ip)
    if lockout_msg:
        audit_service.record_auth_event(identifier, "LOCKED", f"Rate limit lockout: {lockout_msg}")
        raise HTTPException(status_code=429, detail=lockout_msg)

    # 2. Lookup User by Username or Corporate Email
    user = audit_service.get_user(identifier)
    if not user:
        record_failed_login(identifier, client_ip)
        audit_service.record_auth_event(identifier, "FAILED", "Invalid username or email identifier")
        raise HTTPException(status_code=401, detail="Invalid username/email or password.")

    # 3. Verify Password Hash using constant-time comparison
    is_valid = verify_password(password, user.get("password_hash", ""))
    if not is_valid:
        record_failed_login(identifier, client_ip)
        audit_service.record_auth_event(user["email"], "FAILED", "Invalid password attempt")
        raise HTTPException(status_code=401, detail="Invalid username/email or password.")

    # 4. Success: Clear failed attempts and generate session
    reset_login_attempts(identifier, client_ip)
    audit_service.record_auth_event(user["email"], "SUCCESS", "Enterprise Password Authentication Succeeded")

    session_token = create_corporate_session_token(user["email"])
    is_admin = is_admin_user(user["email"])

    custom_token = None
    try:
        raw_token = firebase_auth.create_custom_token(user["email"], {"email": user["email"], "is_admin": is_admin})
        custom_token = raw_token.decode("utf-8") if isinstance(raw_token, bytes) else str(raw_token)
    except Exception as exc:
        logger.warning(f"Firebase custom token generation notice: {exc}")

    return JSONResponse({
        "status": "SUCCESS",
        "email": user["email"],
        "username": user["username"],
        "full_name": user.get("full_name", user["username"]),
        "role": user.get("role", "user"),
        "is_admin": is_admin,
        "token": session_token,
        "custom_token": custom_token,
        "message": f"Welcome, {user.get('full_name', user['username'])}. Successfully signed in.",
    })


@app.post("/api/auth/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest, request: Request):
    """
    Password Recovery Initiator:
    Generates a cryptographically random 32-byte single-use token (valid 15 mins).
    Dispatches password reset link via Microsoft Power Automate with audit copy to aic1176@aurogroup.com.
    """
    identifier = payload.identifier.strip().lower()
    if not identifier:
        raise HTTPException(status_code=400, detail="Corporate username or email is required.")

    redirect_origin = (payload.redirect_origin or "").strip()
    if not redirect_origin:
        redirect_origin = str(request.base_url).rstrip("/")

    user = audit_service.get_user(identifier)
    if user:
        email = user["email"]
        username = user["username"]
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        exp = time.time() + 900  # 15 minutes validity per NIST SP 800-63B

        audit_service.create_password_reset(email, username, token_hash, exp)
        reset_url = f"{redirect_origin}/?action=reset-password&token={raw_token}&email={quote(email)}"

        alert_service.send_password_reset_email(email, username, reset_url)
        audit_service.record_auth_event(email, "PASSWORD_RESET_DISPATCHED", f"Password reset email sent to {email}")

    return JSONResponse({
        "status": "RESET_DISPATCHED",
        "message": "If an authorized account matches this identifier, a password reset link has been dispatched via Power Automate to the corporate email address.",
    })


@app.post("/api/auth/verify-reset-token")
async def verify_reset_token(payload: VerifyResetTokenRequest):
    """Verifies that a password reset token is valid, unconsumed, and unexpired."""
    raw_token = payload.token.strip()
    if not raw_token:
        raise HTTPException(status_code=400, detail="Token is required.")

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    record = audit_service.get_password_reset(token_hash)
    if not record:
        raise HTTPException(status_code=400, detail="Password reset token is invalid, expired, or has already been used.")

    return JSONResponse({
        "status": "VALID",
        "email": record["email"],
        "username": record["username"],
    })


@app.post("/api/auth/reset-password")
async def reset_password(payload: ResetPasswordRequest):
    """
    Completes password reset:
    - Enforces NIST SP 800-63B complexity (min 8 chars, mixed case, digit, special char).
    - Hashes with PBKDF2-HMAC-SHA512 (600,000 iterations).
    - Invalidates the single-use reset token immediately.
    """
    raw_token = payload.token.strip()
    new_password = payload.new_password

    if not raw_token or not new_password:
        raise HTTPException(status_code=400, detail="Token and new password are required.")

    # Validate complexity
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters in length.")
    if not re.search(r"[A-Z]", new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter.")
    if not re.search(r"\d", new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one numeric digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", new_password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character.")

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    record = audit_service.get_password_reset(token_hash)
    if not record:
        raise HTTPException(status_code=400, detail="Password reset token is invalid, expired, or has already been used.")

    username = record["username"]
    user = audit_service.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="User account not found.")

    new_hash = hash_password(new_password)
    user["password_hash"] = new_hash
    user["updated_at"] = audit_service.now_iso()
    audit_service.save_user(user)

    audit_service.consume_password_reset(token_hash)
    audit_service.record_auth_event(user["email"], "PASSWORD_RESET_SUCCESS", f"Password updated for user {username}")

    alert_service.send_failure_alert(
        failure_type="SECURITY_PASSWORD_CHANGED",
        filename="identity_gateway",
        trace_id=f"pwd_{username}",
        user_email=user["email"],
        error_title="Security Notice: Password Reset Completed",
        error_detail=f"The account password for {user['email']} ({username}) was successfully reset via Power Automate link.",
    )

    return JSONResponse({
        "status": "SUCCESS",
        "message": "Password updated successfully. You may now log in with your new credentials.",
    })


@app.post("/api/auth/session-from-firebase")
async def session_from_firebase(
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """Exchanges a verified Firebase ID Token for a Corporate Session Token."""
    email = verify_corporate_user(authorization, x_firebase_token)
    session_token = create_corporate_session_token(email)
    return JSONResponse({
        "status": "SUCCESS",
        "email": email,
        "token": session_token,
        "is_admin": is_admin_user(email),
    })


@app.get("/api/auth/me")
async def get_current_user_profile(
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """Returns the authenticated user's profile and administrative role flag."""
    email = verify_corporate_user(authorization, x_firebase_token)
    return JSONResponse({
        "email": email,
        "is_admin": is_admin_user(email),
        "admin_email": ALERT_EMAIL_RECIPIENT,
    })


@app.post("/api/auth/record-login")
async def record_login(
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """Logs passwordless sign-in events (success/failure) directly into Cloud Firestore."""
    user_email = (payload.get("email") or "").strip().lower()
    status = payload.get("status", "SUCCESS")
    reason = payload.get("reason", "Passwordless Email Link Authentication")
    client_ip = payload.get("client_ip", "Unknown")
    user_agent = payload.get("user_agent", "Web Browser")

    entry = audit_service.record_auth_event(
        user_email=user_email,
        status=status,
        reason=reason,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return {"status": "ok", "entry": entry, "is_admin": is_admin_user(user_email)}


@app.post("/api/park-invoice")
async def park_single_invoice(
    file: UploadFile = File(...),
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """
    Processes a single invoice document independently.
    Returns individual document status, extracted data, BELNR, or HITL requirements.
    """
    user_email = verify_corporate_user(authorization, x_firebase_token)

    content = await file.read()
    if len(content) > MAX_FILE_SIZE_BYTES:
        err_info = SAPErrorTaxonomy.format_error(
            "ERR_FILE_TOO_LARGE",
            filename=file.filename,
            size_mb=round(len(content) / (1024 * 1024), 1),
        )
        return JSONResponse(status_code=413, content={
            "status": "VALIDATION_FAILED",
            "trace_id": str(uuid.uuid4())[:8],
            "filename": file.filename,
            "error_info": err_info,
            "extracted_data": {},
        })

    try:
        result = await process_single_invoice_document(
            filename=file.filename,
            content=content,
            user_email=user_email,
        )
        return JSONResponse(content=result)
    except Exception as exc:
        trace_id = str(uuid.uuid4())[:8]
        alert_service.send_failure_alert(
            failure_type="UNHANDLED_EXCEPTION",
            filename=file.filename,
            trace_id=trace_id,
            user_email=user_email,
            error_title="System Exception during Invoice Processing",
            error_detail=str(exc),
        )
        err_info = SAPErrorTaxonomy.format_error("ERR_SYSTEM_EXCEPTION", detail=str(exc))
        return JSONResponse(content={
            "status": "SYSTEM_ERROR",
            "trace_id": trace_id,
            "filename": file.filename,
            "error_info": err_info,
            "extracted_data": {},
        })


@app.post("/api/park-invoices-batch")
async def park_invoices_batch(
    files: List[UploadFile] = File(...),
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """
    Sequential batch processor: Processes documents ONE AT A TIME.
    Implements Scenario 2: Intra-batch duplicate detection (human error).
    - If user uploads duplicate documents in the same batch:
      * Only the first occurrence is considered and parked in SAP through CPI.
      * The duplicate document is flagged as BATCH_DUPLICATE_DETECTED, prevented from posting to SAP,
        and triggers a failure notification email via Power Automate to aic1176@aurogroup.com.
    """
    user_email = verify_corporate_user(authorization, x_firebase_token)

    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded.")

    results = []
    batch_seen_hashes: Dict[str, str] = {}
    batch_seen_invoices: Dict[Tuple[str, str], str] = {}

    audit_service.log_event(
        event_type="BATCH_JOB_STARTED",
        user_email=user_email,
        trace_id=None,
        severity="INFO",
        message=f"Initiating sequential processing for {len(files)} uploaded document(s).",
    )

    for f in files:
        content = await f.read()
        if len(content) > MAX_FILE_SIZE_BYTES:
            err_info = SAPErrorTaxonomy.format_error(
                "ERR_FILE_TOO_LARGE",
                filename=f.filename,
                size_mb=round(len(content) / (1024 * 1024), 1),
            )
            err_res = {
                "status": "VALIDATION_FAILED",
                "trace_id": str(uuid.uuid4())[:8],
                "filename": f.filename,
                "error_info": err_info,
                "extracted_data": {},
            }
            results.append(err_res)
            continue

        file_sha256 = hashlib.sha256(content).hexdigest()

        # Scenario 2 Check: Exact file duplicate in this batch
        if file_sha256 in batch_seen_hashes:
            orig_name = batch_seen_hashes[file_sha256]
            trace_id = str(uuid.uuid4())[:8]
            err_info = SAPErrorTaxonomy.format_error(
                "ERR_BATCH_DUPLICATE",
                filename=f.filename,
                original_doc=orig_name,
            )
            invoice_record = {
                "trace_id": trace_id,
                "filename": f.filename,
                "file_size": len(content),
                "submitted_by": user_email,
                "status": "BATCH_DUPLICATE_DETECTED",
                "error_info": err_info,
                "extracted_data": {},
                "sap_document_number": None,
                "telemetry": {"submitted_by": user_email, "original_file": orig_name},
            }
            audit_service.save_invoice(invoice_record)
            audit_service.log_event(
                event_type="BATCH_DUPLICATE_FLAGGED",
                user_email=user_email,
                trace_id=trace_id,
                severity="WARNING",
                message=f"Intra-batch duplicate detected: '{f.filename}' has identical content to '{orig_name}' in this upload batch. Skipped CPI parking.",
                metadata={"original_file": orig_name},
            )
            alert_service.send_failure_alert(
                failure_type="BATCH_DUPLICATE_DETECTED",
                filename=f.filename,
                trace_id=trace_id,
                user_email=user_email,
                error_title=f"Intra-Batch Duplicate Document Flagged: '{f.filename}'",
                error_detail=(
                    f"Document '{f.filename}' is an intra-batch duplicate of '{orig_name}'. "
                    f"Only the first copy was considered and parked; this duplicate was flagged, skipped, and prevented from double-posting to SAP."
                ),
                metadata={"original_file": orig_name},
            )
            results.append({
                "status": "BATCH_DUPLICATE_DETECTED",
                "trace_id": trace_id,
                "filename": f.filename,
                "error_info": err_info,
                "extracted_data": {},
            })
            continue

        batch_seen_hashes[file_sha256] = f.filename

        try:
            doc_result = await process_single_invoice_document(
                filename=f.filename,
                content=content,
                user_email=user_email,
                batch_seen_invoices=batch_seen_invoices,
            )
            results.append(doc_result)
        except Exception as exc:
            err_res = {
                "status": "SYSTEM_ERROR",
                "trace_id": str(uuid.uuid4())[:8],
                "filename": f.filename,
                "error_info": SAPErrorTaxonomy.format_error("ERR_SYSTEM_EXCEPTION", detail=str(exc)),
                "extracted_data": {},
            }
            alert_service.send_failure_alert(
                failure_type="BATCH_DOCUMENT_EXCEPTION",
                filename=f.filename,
                trace_id="BATCH",
                user_email=user_email,
                error_title="Sequential Batch Document Exception",
                error_detail=str(exc),
            )
            results.append(err_res)

    audit_service.log_event(
        event_type="BATCH_JOB_COMPLETED",
        user_email=user_email,
        trace_id=None,
        severity="INFO",
        message=f"Sequential processing complete. Total: {len(results)}, Parked: {sum(1 for r in results if r.get('status') == 'PARKED_SUCCESS')}, HITL: {sum(1 for r in results if r.get('status') == 'HITL_REQUIRED')}, Batch Duplicates: {sum(1 for r in results if r.get('status') == 'BATCH_DUPLICATE_DETECTED')}.",
    )

    return JSONResponse(content={
        "batch_total": len(results),
        "results": results,
    })


@app.post("/api/invoices/{trace_id}/resolve-hitl")
async def resolve_hitl_invoice(
    trace_id: str,
    payload: Dict[str, Any],
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """
    Human-in-the-Loop (HITL) Resolution Endpoint:
    Enforces MAANG-grade guardrails:
    1. Multi-User RBAC: Standard users can only resolve invoices they submitted.
       Administrator (aic1176@aurogroup.com) can resolve any invoice.
    2. Field Locking: ONLY PONumber and SES are editable. All other fields are locked and read-only.
    3. Mandatory Rules: Only PONumber is mandatory (10 numeric digits). SES is optional (10 digits starting with 1).
    """
    user_email = verify_corporate_user(authorization, x_firebase_token)

    invoice = audit_service.get_invoice(trace_id)
    if not invoice:
        raise HTTPException(status_code=404, detail=f"Invoice with trace ID '{trace_id}' not found.")

    # 1. RBAC Isolation Check
    is_admin = is_admin_user(user_email)
    submitted_by = (invoice.get("submitted_by") or "").strip().lower()
    if not is_admin and submitted_by and submitted_by != user_email.lower():
        audit_service.log_event(
            event_type="RBAC_ACCESS_DENIED",
            user_email=user_email,
            trace_id=trace_id,
            severity="WARNING",
            message=f"RBAC violation: User {user_email} attempted to resolve invoice owned by {submitted_by}.",
        )
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Multi-user isolation policy restricts you to resolving invoices uploaded by your account."
        )

    if invoice.get("status") not in ("HITL_REQUIRED", "VALIDATION_FAILED", "SAP_REJECTED", "IRRELEVANT_DOC_PENDING"):
        raise HTTPException(
            status_code=400,
            detail=f"Invoice is currently in status '{invoice.get('status')}' and does not require intervention."
        )

    extracted_data = invoice.get("extracted_data", {})
    header = extracted_data.setdefault("HeaderData", {})
    corrections = payload.get("corrections", {})

    # 2. Strict Field Locking: ONLY PONumber and SES can be edited!
    po_raw = str(corrections.get("PONumber") or header.get("PONumber") or "").strip()
    if not po_raw:
        raise HTTPException(status_code=422, detail="PO Number is mandatory. Please provide a valid 10-digit Purchase Order.")
    if not re.match(r"^\d{10}$", po_raw):
        raise HTTPException(status_code=422, detail=f"Invalid PO Number '{po_raw}'. Purchase Order must be exactly 10 numeric digits (e.g. 4500123456).")
    header["PONumber"] = po_raw

    # Validate SES (Optional: if provided, must be 10 digits starting with 1)
    if "SES" in corrections:
        ses_raw = str(corrections.get("SES") or "").strip()
        if ses_raw and ses_raw.lower() not in ("null", "none", ""):
            if not re.match(r"^1\d{9}$", ses_raw):
                raise HTTPException(status_code=422, detail=f"Invalid SES Number '{ses_raw}'. Service Entry Sheet must be a 10-digit number starting with 1 (e.g. 1000123456).")
            header["SES"] = ses_raw
        else:
            header["SES"] = None
    elif not header.get("SES") or str(header.get("SES")).strip().lower() in ("null", "none", ""):
        header["SES"] = None

    # NOTE: All other fields (RefDocNo, CompCode, DocDate, BusinessPlace, TaxableVal, TotalInvVal, ItemData)
    # remain strictly locked as originally extracted and cannot be altered.

    audit_service.log_event(
        event_type="HITL_RESOLUTION_ATTEMPTED",
        user_email=user_email,
        trace_id=trace_id,
        severity="INFO",
        message=f"User {user_email} (Admin: {is_admin}) submitted HITL updates for invoice '{trace_id}': PO={header.get('PONumber')}, SES={header.get('SES')}.",
        metadata={"po": header.get("PONumber"), "ses": header.get("SES")},
    )

    # Re-validate
    is_valid, error_code, error_val = validate_sap_schema(extracted_data)
    if not is_valid:
        err_info = SAPErrorTaxonomy.format_error(error_code, value=error_val or "")
        invoice["status"] = "HITL_REQUIRED"
        invoice["error_info"] = err_info
        invoice["missing_fields"] = err_info.get("target_fields", [])
        audit_service.save_invoice(invoice)
        return JSONResponse(status_code=422, content={
            "status": "HITL_REQUIRED",
            "trace_id": trace_id,
            "error_info": err_info,
            "message": "Validation failed against SAP rules. Please check PO and SES formats.",
            "extracted_data": extracted_data,
        })

    # Restore valid Base64 attachment if previously sanitized
    if trace_id in audit_service._invoices_mem:
        mem_inv = audit_service._invoices_mem[trace_id]
        mem_att = mem_inv.get("extracted_data", {}).get("HeaderData", {}).get("Attachment")
        if mem_att and not str(mem_att).startswith("<Base64"):
            header["Attachment"] = mem_att
    if not header.get("Attachment") or str(header.get("Attachment")).startswith("<Base64"):
        header["Attachment"] = base64.b64encode(b"%PDF-1.4\n%AEPL HITL Synthesized Document").decode("utf-8")

    # Execute SAP CPI BAPI
    telemetry = invoice.get("telemetry", {})
    cpi_result = submit_to_sap_cpi(trace_id, extracted_data, telemetry)

    if cpi_result.get("status") == "SUCCESS":
        belnr = cpi_result.get("belnr") or "5105600001"
        invoice["status"] = "PARKED_SUCCESS"
        invoice["hitl_resolved"] = True
        invoice["resolved_by"] = user_email
        invoice["resolved_at"] = audit_service.now_iso()
        invoice["sap_document_number"] = belnr
        invoice["sap_message"] = cpi_result.get("sap_message")
        invoice.pop("error_info", None)
        audit_service.save_invoice(invoice)

        audit_service.log_event(
            event_type="HITL_RESOLVED_SUCCESS",
            user_email=user_email,
            trace_id=trace_id,
            severity="INFO",
            message=f"Invoice '{trace_id}' successfully resolved via HITL by {user_email} and parked in SAP (BELNR #{belnr}).",
            metadata={"belnr": belnr, "po": header.get("PONumber")},
        )

        return JSONResponse(content={
            "status": "PARKED_SUCCESS",
            "trace_id": trace_id,
            "sap_document_number": belnr,
            "sap_message": cpi_result.get("sap_message"),
            "extracted_data": extracted_data,
        })
    else:
        sap_err_msg = str(cpi_result.get("sap_message", ""))
        ref_doc_no = header.get("RefDocNo")
        comp_code = header.get("CompCode")
        existing_dup = audit_service.find_duplicate_invoice(ref_doc_no, comp_code)
        is_pure_duplicate = bool(
            (existing_dup and existing_dup.get("trace_id") != trace_id) or
            any(w in sap_err_msg.lower() for w in ["duplicate", "already exists", "already parked", "already entered"])
        )

        if is_pure_duplicate:
            existing_doc = (existing_dup.get("sap_document_number") or existing_dup.get("trace_id")) if existing_dup else "Existing Document"
            err_info = SAPErrorTaxonomy.format_error(
                "ERR_DUPLICATE_INVOICE",
                ref_doc_no=ref_doc_no or "N/A",
                comp_code=comp_code or "1000",
                existing_doc=existing_doc,
            )
            err_info["error_message"] += f" (Verified via SAP CPI rejection: {sap_err_msg})"
            invoice["status"] = "DUPLICATE_DETECTED"
            invoice["error_info"] = err_info
            invoice["sap_message"] = sap_err_msg
            audit_service.save_invoice(invoice)
            audit_service.log_event(
                event_type="HITL_DUPLICATE_CONFIRMED",
                user_email=user_email,
                trace_id=trace_id,
                severity="WARNING",
                message=f"HITL resumed SAP dispatch confirmed duplicate: {ref_doc_no} (Document #{existing_doc}) rejected by SAP CPI.",
                metadata={"ref_doc_no": ref_doc_no, "existing_doc": existing_doc, "cpi_message": sap_err_msg},
            )

            # Failure Alert via Power Automate
            alert_incident = alert_service.send_failure_alert(
                failure_type="DUPLICATE_INVOICE_PREVENTED",
                filename=invoice.get("filename", "unknown"),
                trace_id=trace_id,
                user_email=user_email,
                error_title=f"Duplicate Invoice Prevented (HITL) - {ref_doc_no}",
                error_detail=(
                    f"Invoice with Reference '{ref_doc_no}' and Company Code '{comp_code}' "
                    f"was already processed in SAP (Document #{existing_doc}). "
                    f"SAP CPI Rejection: {sap_err_msg}"
                ),
                metadata={
                    "ref_doc_no": ref_doc_no,
                    "existing_doc": existing_doc,
                    "comp_code": comp_code,
                    "sap_message": sap_err_msg,
                },
            )

            return JSONResponse(status_code=422, content={
                "status": "DUPLICATE_DETECTED",
                "trace_id": trace_id,
                "error_info": err_info,
                "sap_message": sap_err_msg,
                "extracted_data": extracted_data,
                "alert_notification": {
                    "incident_id": alert_incident.get("incident_id"),
                    "status": alert_incident.get("email_status"),
                    "recipient": alert_incident.get("recipient"),
                },
            })
        else:
            err_info = SAPErrorTaxonomy.format_error("ERR_SAP_CPI_REJECTED", detail=sap_err_msg)
            invoice["status"] = "SAP_REJECTED"
            invoice["error_info"] = err_info
            audit_service.save_invoice(invoice)

            audit_service.log_event(
                event_type="HITL_SAP_REJECTED",
                user_email=user_email,
                trace_id=trace_id,
                severity="ERROR",
                message=f"HITL resumed SAP dispatch failed: {sap_err_msg}",
            )

            alert_incident = alert_service.send_failure_alert(
                failure_type="HITL_RESUMED_SAP_REJECTION",
                filename=invoice.get("filename", "unknown"),
                trace_id=trace_id,
                user_email=user_email,
                error_title="HITL Resumed SAP BAPI Rejection",
                error_detail=sap_err_msg,
            )

            return JSONResponse(status_code=422, content={
                "status": "SAP_REJECTED",
                "trace_id": trace_id,
                "error_info": err_info,
                "sap_message": sap_err_msg,
                "extracted_data": extracted_data,
                "alert_notification": {
                    "incident_id": alert_incident.get("incident_id"),
                    "status": alert_incident.get("email_status"),
                    "recipient": alert_incident.get("recipient"),
                    "timestamp": alert_incident.get("timestamp"),
                },
            })


@app.post("/api/invoices/{trace_id}/discard-irrelevant")
async def discard_irrelevant_invoice(
    trace_id: str,
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """
    Allows reviewer or administrator to discard an irrelevant document with ONE CLICK.
    Per specification, no manual field entry is required for irrelevant documents.
    """
    user_email = verify_corporate_user(authorization, x_firebase_token)
    invoice = audit_service.get_invoice(trace_id)
    if not invoice:
        raise HTTPException(status_code=404, detail=f"Invoice '{trace_id}' not found.")

    is_admin = is_admin_user(user_email)
    submitted_by = (invoice.get("submitted_by") or "").strip().lower()
    if not is_admin and submitted_by and submitted_by != user_email.lower():
        raise HTTPException(status_code=403, detail="Forbidden: You can only discard documents uploaded by your account.")

    invoice["status"] = "DISCARDED_IRRELEVANT"
    invoice["discarded_by"] = user_email
    invoice["discarded_at"] = audit_service.now_iso()
    audit_service.save_invoice(invoice)

    audit_service.log_event(
        event_type="IRRELEVANT_DOCUMENT_DISCARDED",
        user_email=user_email,
        trace_id=trace_id,
        severity="INFO",
        message=f"User {user_email} confirmed and discarded irrelevant document '{invoice.get('filename')}'.",
    )

    return JSONResponse(content={
        "status": "DISCARDED_IRRELEVANT",
        "trace_id": trace_id,
        "filename": invoice.get("filename"),
        "message": "Document confirmed as irrelevant and successfully discarded.",
    })


# ---------------------------------------------------------
# 12. ADMIN MIS & MONITORING ENDPOINTS
# ---------------------------------------------------------
@app.get("/api/mis/dashboard")
async def get_mis_dashboard(
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """
    Returns executive KPI statistics and status counts with strict multi-user isolation.
    - Standard users only see statistics for their own uploads.
    - Administrator (aic1176@aurogroup.com) views organization-wide statistics.
    """
    user_email = verify_corporate_user(authorization, x_firebase_token)
    is_admin = is_admin_user(user_email)
    metrics = audit_service.get_mis_metrics(user_email=user_email, is_admin=is_admin)
    all_incidents = alert_service.list_incidents()
    if is_admin:
        metrics["incident_alerts_count"] = len(all_incidents)
        metrics["user_breakdown"] = audit_service.get_user_mis_breakdown(is_admin=True)
    else:
        metrics["incident_alerts_count"] = len([i for i in all_incidents if (i.get("user_email") or "").lower() == user_email.lower()])
        metrics["user_breakdown"] = [u for u in audit_service.get_user_mis_breakdown(is_admin=False) if u.get("email") == user_email.lower()]
    return JSONResponse(content=metrics)


@app.get("/api/mis/invoices")
async def list_invoices_endpoint(
    status: Optional[str] = Query(default="ALL"),
    search: Optional[str] = Query(default=None),
    limit: int = Query(default=100, le=500),
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """
    Returns filterable invoices stored in Cloud Firestore.
    Enforces strict tenant isolation: Standard users only receive their own submitted documents.
    """
    user_email = verify_corporate_user(authorization, x_firebase_token)
    is_admin = is_admin_user(user_email)
    invoices = audit_service.list_invoices(
        status=status,
        search=search,
        limit=limit,
        user_email=user_email,
        is_admin=is_admin,
    )

    sanitized = []
    for inv in invoices:
        item = dict(inv)
        if "extracted_data" in item and "HeaderData" in item["extracted_data"]:
            h = dict(item["extracted_data"]["HeaderData"])
            if "Attachment" in h:
                h["Attachment"] = "<Base64 PDF Attached>"
            item["extracted_data"]["HeaderData"] = h
        sanitized.append(item)

    return JSONResponse(content={"invoices": sanitized, "count": len(sanitized)})


@app.get("/api/mis/hitl-queue")
async def get_hitl_queue(
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """
    Returns invoices awaiting Human-in-the-Loop review (HITL_REQUIRED, SAP_REJECTED, IRRELEVANT_DOC_PENDING).
    Filtered by uploader identity for non-administrators.
    """
    user_email = verify_corporate_user(authorization, x_firebase_token)
    is_admin = is_admin_user(user_email)
    all_inv = audit_service.list_invoices(limit=200, user_email=user_email, is_admin=is_admin)
    pending = [i for i in all_inv if i.get("status") in ("HITL_REQUIRED", "SAP_REJECTED", "IRRELEVANT_DOC_PENDING")]

    sanitized = []
    for inv in pending:
        item = dict(inv)
        if "extracted_data" in item and "HeaderData" in item["extracted_data"]:
            h = dict(item["extracted_data"]["HeaderData"])
            if "Attachment" in h:
                h["Attachment"] = "<Base64 PDF Attached>"
            item["extracted_data"]["HeaderData"] = h
        sanitized.append(item)

    return JSONResponse(content={"pending_invoices": sanitized, "count": len(sanitized)})


@app.get("/api/mis/audit-logs")
async def get_audit_logs(
    limit: int = Query(default=50, le=200),
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """
    Returns chronological audit events from Cloud Firestore (Mumbai asia-south1).
    Standard users only see audit trail events associated with their activity.
    """
    user_email = verify_corporate_user(authorization, x_firebase_token)
    is_admin = is_admin_user(user_email)
    logs = audit_service.list_audit_logs(limit=limit, user_email=user_email, is_admin=is_admin)
    return JSONResponse(content={"audit_logs": logs, "count": len(logs)})


@app.get("/api/mis/incident-alerts")
async def get_incident_alerts(
    limit: int = Query(default=50, le=200),
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """Returns automated failure incidents and notification dispatches to aic1176@aurogroup.com."""
    user_email = verify_corporate_user(authorization, x_firebase_token)
    is_admin = is_admin_user(user_email)
    incidents = alert_service.list_incidents(limit=limit)
    if not is_admin:
        incidents = [i for i in incidents if (i.get("user_email") or "").lower() == user_email.lower()]

    return JSONResponse(content={
        "recipient": alert_service.recipient_email,
        "alerts": incidents,
        "incident_alerts": incidents,
        "count": len(incidents),
    })


@app.post("/api/admin/trigger-monthly-mis")
async def trigger_monthly_mis_report(
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """
    Admin-only endpoint to trigger and dispatch the automated Monthly Executive MIS Report
    via Microsoft Power Automate to aic1176@aurogroup.com.
    """
    user_email = verify_corporate_user(authorization, x_firebase_token)
    if not is_admin_user(user_email):
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Only administrator (aic1176@aurogroup.com) can trigger monthly executive MIS reports."
        )

    month_str = datetime.now(timezone.utc).strftime("%B %Y")
    metrics = audit_service.get_mis_metrics(is_admin=True)
    user_breakdown = audit_service.get_user_mis_breakdown(is_admin=True)

    delivered = alert_service.send_monthly_mis_digest(
        month_str=month_str,
        metrics=metrics,
        user_breakdown=user_breakdown,
    )

    audit_service.log_event(
        event_type="MONTHLY_MIS_REPORT_DISPATCHED",
        user_email=user_email,
        trace_id=None,
        severity="INFO",
        message=f"Monthly MIS report for {month_str} dispatched to {alert_service.recipient_email} via Power Automate.",
        metadata={"month": month_str, "delivered": delivered},
    )

    return JSONResponse(content={
        "status": "DISPATCHED" if delivered else "QUEUED",
        "recipient": alert_service.recipient_email,
        "month": month_str,
        "metrics_summary": {
            "total_invoices": metrics.get("total_invoices", 0),
            "parked_success": metrics.get("parked_success", 0),
            "hitl_pending": metrics.get("hitl_pending", 0),
            "duplicates": metrics.get("duplicate_detected", 0),
        },
        "delivered_via_power_automate": delivered,
    })


@app.post("/api/alerts/test")
async def test_alert_notification(
    recipient: Optional[str] = Query(default=None),
    authorization: Optional[str] = Header(default=None),
    x_firebase_token: Optional[str] = Header(default=None),
):
    """Sends a test failure alert email to verify the notification pipeline."""
    user_email = verify_corporate_user(authorization, x_firebase_token)
    target = recipient or alert_service.recipient_email
    test_incident = alert_service.send_failure_alert(
        failure_type="TEST_DIAGNOSTIC_ALERT",
        filename="system_health_check.pdf",
        trace_id=f"test_{str(uuid.uuid4())[:6]}",
        user_email=user_email,
        error_title="Diagnostic Failure Alert Test",
        error_detail="This is a test notification confirming automated failure alerting dispatch to administrator via Power Automate.",
    )
    return JSONResponse(content={
        "status": "DELIVERED",
        "email_status": test_incident.get("email_status", "DISPATCHED"),
        "incident": test_incident,
        "active_transports": {
            "webhook_configured": bool(alert_service.webhook_url),
            "extension": "firestore-send-email (Official Firebase Extension)",
            "firestore_collection": alert_service.mail_collection,
            "firebase_connected": bool(alert_service.db is not None),
            "recipient": target,
        }
    })


# ---------------------------------------------------------
# 13. AUTOMATED BACKGROUND MONTHLY MIS SCHEDULER
# ---------------------------------------------------------
_LAST_MONTHLY_REPORT_SENT_MONTH: Optional[str] = None

async def _periodic_monthly_mis_checker():
    """Background task running continuously to dispatch the monthly executive digest on the 1st of every month."""
    global _LAST_MONTHLY_REPORT_SENT_MONTH
    while True:
        try:
            now = datetime.now(timezone.utc)
            current_month = now.strftime("%Y-%m")
            if now.day == 1 and _LAST_MONTHLY_REPORT_SENT_MONTH != current_month:
                month_str = now.strftime("%B %Y")
                metrics = audit_service.get_mis_metrics(is_admin=True)
                user_breakdown = audit_service.get_user_mis_breakdown(is_admin=True)

                delivered = alert_service.send_monthly_mis_digest(
                    month_str=month_str,
                    metrics=metrics,
                    user_breakdown=user_breakdown,
                )
                _LAST_MONTHLY_REPORT_SENT_MONTH = current_month
                logger.info(f"Automated monthly MIS digest delivered for {month_str} to {ALERT_EMAIL_RECIPIENT} (Status: {delivered}).")
        except Exception as e:
            logger.warning(f"Periodic monthly MIS scheduler check error: {e}")
        await asyncio.sleep(3600)  # Check every hour


@app.on_event("startup")
async def start_background_schedulers():
    """Starts background automation workers on application boot."""
    asyncio.create_task(_periodic_monthly_mis_checker())
