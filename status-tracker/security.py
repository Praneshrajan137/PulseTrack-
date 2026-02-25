"""
security.py — HMAC-SHA256 Signature Verification + Content-Type Enforcement

Security Architecture:
  - Content-Type validated BEFORE HMAC computation (cheapest-first ordering).
    Non-JSON bodies are rejected with HTTP 415, not the confusing 422 from Pydantic.
  - Raw request body bytes extracted BEFORE any JSON deserialization.
    Any parse/re-serialize step alters whitespace or key ordering, producing a
    different hash that rejects all legitimate payloads. Raw bytes are canonical.
  - HMAC-SHA256 computed over raw bytes using the pre-shared WEBHOOK_SECRET.
  - Constant-time comparison via hmac.compare_digest() neutralizes timing oracles.
  - All requests with missing or invalid signatures rejected with HTTP 401.
  - Supports multiple signature header naming conventions (provider-agnostic design).

Timing Attack Defense:
  Standard string comparison (==) short-circuits on the first mismatched character.
  An attacker measuring nanosecond response time differences across millions of
  requests can deduce the correct signature character by character. hmac.compare_digest()
  always takes constant time regardless of where the mismatch occurs.

WEBHOOK_SECRET Lifecycle:
  - Development: omit from .env → verification bypassed with WARNING (dev-mode).
  - Production: must be set or startup validation fails (enforced in main.py lifespan).
  - Rotation: use verify_hmac_signature_dual_key() during transition window only.

Change log:
  v2.1 — GAP-005: Added Content-Type validation. Requests with non-JSON Content-Type
         are rejected with HTTP 415 before HMAC computation. Validation order is:
         Content-Type check → secret presence check → signature check. This ordering
         rejects obviously wrong requests at minimum cost.
"""

import os
import hmac
import hashlib
import logging
from typing import Optional

from fastapi import Request, HTTPException

logger = logging.getLogger(__name__)

# All known signature header naming conventions used by webhook providers.
# Tried in order; the first match wins. Add provider-specific headers here
# without modifying any other part of the application.
SIGNATURE_HEADER_CANDIDATES: list[str] = [
    "x-hub-signature-256",       # GitHub, Atlassian Statuspage (primary)
    "x-statuspage-signature",     # Atlassian Statuspage (alternate)
    "x-webhook-signature",        # Generic fallback
]


async def verify_hmac_signature(request: Request) -> None:
    """
    FastAPI dependency enforcing Content-Type and HMAC-SHA256 on every POST /webhook.

    This function MUST be `async def` because it calls `await request.body()`.
    Declaring it as synchronous `def` causes a TypeError at runtime when the
    async body read is attempted inside a sync context.

    Validation order (cheapest-to-most-expensive):
      1. Content-Type must include 'application/json' → HTTP 415 if not.
      2. WEBHOOK_SECRET must be present → dev-bypass WARNING if absent.
      3. Signature header must be present → HTTP 401 if absent.
      4. HMAC must match computed value → HTTP 401 if mismatch.

    Raises:
        HTTPException(415): Content-Type header does not include application/json.
        HTTPException(401): WEBHOOK_SECRET is set and signature is missing or wrong.

    Dev bypass:
        When WEBHOOK_SECRET is absent, HMAC verification is skipped with a WARNING.
        Content-Type validation still applies — it is not authentication-dependent.
        In production, main.py lifespan enforces WEBHOOK_SECRET is set at startup.
    """
    # ── Step 1: Content-Type validation (GAP-005) ─────────────────────────────
    # Note: Content-Type may include charset suffix (e.g. "application/json; charset=utf-8")
    # Use `in` for substring matching, not exact equality.
    content_type: str = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        logger.error(
            f"Request rejected: Content-Type '{content_type}' is not application/json. "
            "Atlassian Statuspage always sends application/json. "
            "This may indicate a misconfigured client or a probing attempt."
        )
        raise HTTPException(
            status_code=415,
            detail="Unsupported Media Type. Expected Content-Type: application/json.",
        )

    # ── Step 2: Secret presence check ────────────────────────────────────────
    secret: Optional[str] = os.environ.get("WEBHOOK_SECRET")

    if not secret:
        logger.warning(
            "SECURITY WARNING: WEBHOOK_SECRET is not configured. "
            "HMAC verification is BYPASSED. Acceptable for local development only. "
            "All requests are being processed without cryptographic authentication."
        )
        return

    # ── Step 3: Signature header presence check ───────────────────────────────
    signature_header: Optional[str] = None
    for candidate in SIGNATURE_HEADER_CANDIDATES:
        value = request.headers.get(candidate)
        if value:
            signature_header = value
            break

    if not signature_header:
        logger.error(
            "Request rejected: No signature header found. "
            f"Searched headers: {SIGNATURE_HEADER_CANDIDATES}. "
            "This may indicate an unauthenticated POST or an unsupported provider."
        )
        raise HTTPException(
            status_code=401,
            detail="Missing signature header. Webhook signature is required.",
        )

    # ── Step 4: HMAC computation and constant-time comparison ─────────────────
    # CRITICAL: Extract raw bytes BEFORE any JSON parsing.
    # The provider computed the HMAC over the exact byte sequence it transmitted.
    # Any transformation (parse/re-serialize) produces different bytes → different hash.
    raw_body: bytes = await request.body()

    computed_mac: str = hmac.new(
        key=secret.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    # Normalize to match provider's format: "sha256=" prefix or bare hex.
    expected_signature: str = (
        f"sha256={computed_mac}"
        if signature_header.startswith("sha256=")
        else computed_mac
    )

    # NEVER use == for cryptographic comparison — timing oracle attack vector.
    if not hmac.compare_digest(expected_signature, signature_header):
        logger.error(
            "Request rejected: HMAC signature mismatch. "
            "Payload was tampered in transit, signed with an incorrect secret, "
            "or originated from an unauthorized source."
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid signature. Request rejected.",
        )

    logger.debug("HMAC-SHA256 signature verified successfully.")


async def verify_hmac_signature_dual_key(request: Request) -> None:
    """
    Zero-downtime secret rotation variant of verify_hmac_signature.

    USE ONLY during an active key rotation window. Revert to the single-key
    version once rotation is confirmed complete.

    HOW IT WORKS:
      1. Configure WEBHOOK_SECRET_PRIMARY  (new key — register this with Atlassian)
      2. Configure WEBHOOK_SECRET_SECONDARY (old key — still active on Atlassian edge)
      3. Switch main.py Depends() to this function and deploy
      4. Register the new key with Atlassian Statuspage
      5. Wait 5–15 minutes for propagation across all Atlassian edge nodes
      6. Remove WEBHOOK_SECRET_SECONDARY from environment
      7. Revert Depends() to verify_hmac_signature and redeploy

    During the rotation window, ANY request signed with EITHER key is authenticated.
    This ensures zero events are dropped while Atlassian's edge propagates the new key.

    Content-Type validation is applied identically to the single-key variant.

    Raises:
        HTTPException(415): Content-Type is not application/json.
        HTTPException(401): Neither key produces a matching signature, or no header.
    """
    # Content-Type check applies regardless of rotation mode
    content_type: str = request.headers.get("content-type", "")
    if "application/json" not in content_type:
        raise HTTPException(
            status_code=415,
            detail="Unsupported Media Type. Expected Content-Type: application/json.",
        )

    primary: Optional[str] = os.environ.get("WEBHOOK_SECRET_PRIMARY")
    secondary: Optional[str] = os.environ.get("WEBHOOK_SECRET_SECONDARY")

    if not primary and not secondary:
        logger.warning(
            "SECURITY WARNING: Neither WEBHOOK_SECRET_PRIMARY nor WEBHOOK_SECRET_SECONDARY "
            "is configured. HMAC verification BYPASSED (dev mode)."
        )
        return

    # Locate signature header
    signature_header: Optional[str] = None
    for candidate in SIGNATURE_HEADER_CANDIDATES:
        value = request.headers.get(candidate)
        if value:
            signature_header = value
            break

    if not signature_header:
        raise HTTPException(
            status_code=401,
            detail="Missing signature header. Webhook signature is required.",
        )

    raw_body: bytes = await request.body()

    def _compute_sig(secret_key: str) -> str:
        """Compute the HMAC-SHA256 signature string for the given key."""
        mac = hmac.new(
            key=secret_key.encode("utf-8"),
            msg=raw_body,
            digestmod=hashlib.sha256,
        ).hexdigest()
        return f"sha256={mac}" if signature_header.startswith("sha256=") else mac

    # Try primary key first (the newly registered key)
    secrets_to_try: list[tuple[str, str]] = []
    if primary:
        secrets_to_try.append(("PRIMARY", primary))
    if secondary:
        secrets_to_try.append(("SECONDARY", secondary))

    for key_label, secret_value in secrets_to_try:
        expected = _compute_sig(secret_value)
        if hmac.compare_digest(expected, signature_header):
            logger.debug(f"HMAC verified using {key_label} key during rotation window.")
            return

    logger.error(
        "Request rejected: Signature mismatch against both PRIMARY and SECONDARY keys. "
        "Rotation window may have expired or payload is from an unauthorized source."
    )
    raise HTTPException(
        status_code=401,
        detail="Invalid signature. Request rejected.",
    )
