"""
processor.py — Pure Business Logic: Status Update Formatting, Dedup, and Output

Design Principles:
  - Stateless per-invocation: no per-call mutable state beyond the module-level
    dedup cache and MONITORED_PRODUCTS list (both intentionally module-scoped).
  - Synchronous: `def` (not `async def`) — no I/O awaits. FastAPI BackgroundTasks
    executes this in a thread pool, never blocking the async event loop.
  - Zero dependencies on FastAPI, Pydantic, or any web framework.
  - Given the same unique WebhookPayload event ID, this function produces output
    exactly once — duplicate deliveries are detected and silently discarded.

Thread Safety:
  This module runs inside FastAPI's BackgroundTasks thread pool executor.
  Multiple concurrent webhook deliveries can call process_status_update() simultaneously.
  ALL shared mutable state (_seen_event_ids, _seen_event_ids_order) MUST be protected
  by threading.Lock. Using asyncio.Lock here would be incorrect and non-thread-safe.

Execution Context:
  Called exclusively through FastAPI's BackgroundTasks mechanism.
  HTTP 202 is returned to Atlassian BEFORE this function begins execution.

Output Format (immutable specification):
  [YYYY-MM-DDTHH:MM:SSZ] Product: {component_name}
  Status: {Normalized status string}

  (blank line follows each entry)

Change log:
  v2.1 — GAP-004: Thread-safe idempotency guard using bounded LRU-style set.
         Atlassian retries on 5xx or timeout. Without this guard, a transient
         error causes duplicate log entries for the same event. Cache holds
         the last 500 event IDs. No external dependency required.

  v2.1 — GAP-007: MONITORED_PRODUCTS now driven by MONITORED_KEYWORDS env var.
         Loaded once at module import. Operators change the filter via env var
         update + restart — no code change, no container rebuild required.
"""

import os
import datetime
import logging
import threading
from typing import Optional

from models import WebhookPayload

logger = logging.getLogger(__name__)


# ── Deduplication Cache (GAP-004) ────────────────────────────────────────────
#
# Atlassian Statuspage retries webhook delivery on 5xx response or network timeout.
# The same component_update.id or incident.id arrives more than once in these cases.
# This bounded in-memory cache prevents duplicate log entries without requiring Redis
# or any external data store — appropriate for this single-process deployment model.
#
# Thread safety requirement: process_status_update() runs in a thread pool executor.
# Multiple concurrent invocations can reach the dedup check simultaneously. All
# mutations of _seen_event_ids MUST be protected by threading.Lock (NOT asyncio.Lock,
# which is not thread-safe in a synchronous thread pool context).
#
# Capacity: last _DEDUP_CACHE_MAX IDs retained. Oldest evicted first (FIFO) when
# capacity is reached, preventing unbounded memory growth in long-running processes.

_dedup_lock: threading.Lock = threading.Lock()
_seen_event_ids: set[str] = set()
_seen_event_ids_order: list[str] = []
_DEDUP_CACHE_MAX: int = 500


def _is_duplicate_event(event_id: str) -> bool:
    """
    Thread-safe idempotency check. Returns True if this event_id was already processed.

    First encounter: registers the ID in the cache, returns False (proceed with processing).
    Subsequent encounters: returns True (discard this delivery silently).

    FIFO eviction: when _DEDUP_CACHE_MAX is reached, the oldest registered ID is
    removed from both the set (O(1) lookup) and the order list (O(1) pop from front).

    Args:
        event_id: Atlassian event UUID from component_update.id or incident.id.

    Returns:
        True  — duplicate delivery; caller should discard and log at DEBUG.
        False — first occurrence; caller should proceed with full processing.
    """
    with _dedup_lock:
        if event_id in _seen_event_ids:
            return True
        # Evict oldest entry if at capacity (FIFO)
        if len(_seen_event_ids) >= _DEDUP_CACHE_MAX:
            evicted = _seen_event_ids_order.pop(0)
            _seen_event_ids.discard(evicted)
        _seen_event_ids.add(event_id)
        _seen_event_ids_order.append(event_id)
        return False


# ── Monitored Products Filter (GAP-007) ──────────────────────────────────────
#
# Loaded ONCE at module import from the MONITORED_KEYWORDS environment variable.
# Format: comma-separated keywords, case-insensitive substring match against
# component names. "api" matches "OpenAI API - Chat Completions".
#
# If MONITORED_KEYWORDS is absent or empty after stripping, the hardcoded default
# list is used. This provides a safe, functional default with no configuration required.
#
# Set MONITORED_KEYWORDS to a single comma to get empty-after-strip tokens, which
# triggers the fallback to defaults. Use a deliberate non-matching keyword like
# "__DISABLED__" to suppress all component logging (incidents still pass through).
#
# Changing the filter: update MONITORED_KEYWORDS in environment + restart process.
# No code change. No container rebuild. No redeployment of source.

_DEFAULT_MONITORED_KEYWORDS: list[str] = [
    "api",
    "chat completions",
    "completions",
    "assistants",
    "embeddings",
    "fine-tuning",
    "images",
    "audio",
    "moderation",
    "realtime",
]

_env_keywords_raw: str = os.environ.get("MONITORED_KEYWORDS", "").strip()

if _env_keywords_raw:
    # Parse comma-separated list: strip whitespace, lowercase, discard empty tokens
    MONITORED_PRODUCTS: Optional[list[str]] = [
        k.strip().lower() for k in _env_keywords_raw.split(",") if k.strip()
    ]
    if not MONITORED_PRODUCTS:
        # Edge case: "MONITORED_KEYWORDS=," — all tokens empty after strip. Use defaults.
        MONITORED_PRODUCTS = _DEFAULT_MONITORED_KEYWORDS
else:
    MONITORED_PRODUCTS = _DEFAULT_MONITORED_KEYWORDS


# ── Pure Helper Functions ─────────────────────────────────────────────────────

def _normalize_status(raw_status: str) -> str:
    """
    Converts Atlassian snake_case status strings to human-readable sentence case.

    Atlassian uses underscore-separated lowercase status codes. The required output
    format mandates spaces with only the first letter capitalized (sentence case,
    NOT title case — "Degraded performance" NOT "Degraded Performance").

    Examples:
        'degraded_performance' -> 'Degraded performance'
        'partial_outage'       -> 'Partial outage'
        'operational'          -> 'Operational'
        'under_maintenance'    -> 'Under maintenance'
        'major_outage'         -> 'Major outage'
        'investigating'        -> 'Investigating'
    """
    return raw_status.replace("_", " ").strip().capitalize()


def _get_utc_timestamp() -> str:
    """
    Returns the current UTC time formatted as [YYYY-MM-DDTHH:MM:SSZ].

    IMPLEMENTATION NOTE: The "Z" suffix is a HARD-CODED LITERAL character in the
    strftime format string — do NOT replace it with %Z. On most platforms, `%Z`
    produces "UTC" (the string), which is NOT valid ISO 8601 Zulu notation.
    The datetime object is explicitly constructed with datetime.timezone.utc to
    guarantee UTC correctness regardless of the server's local timezone setting.
    """
    now: datetime.datetime = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("[%Y-%m-%dT%H:%M:%SZ]")


def _is_monitored_product(component_name: str) -> bool:
    """
    Returns True if this component name matches any keyword in MONITORED_PRODUCTS.

    Matching semantics:
      - Case-insensitive: "API" matches keyword "api"
      - Substring: "OpenAI API - Chat Completions" matches keyword "chat completions"
      - MONITORED_PRODUCTS = None: disabled — accept all components unconditionally

    HTTP 202 is always returned by the route handler regardless of this filter.
    Non-matching components are acknowledged to Atlassian but produce no console output.
    """
    if MONITORED_PRODUCTS is None:
        return True
    name_lower = component_name.lower()
    return any(keyword in name_lower for keyword in MONITORED_PRODUCTS)


# ── Core Processing Function ──────────────────────────────────────────────────

def process_status_update(payload: WebhookPayload) -> None:
    """
    Core processing function. Executed as a FastAPI BackgroundTask in a thread pool.

    Priority logic:
      1. Component Update (both `component` and `component_update` present):
         Most specific event type. Reports the exact API product and its new status.
         Subject to MONITORED_PRODUCTS filtering and deduplication by
         component_update.id (if the field is present in the payload).

      2. Platform Incident (`incident` present):
         Broad outage declaration. Always reported regardless of MONITORED_PRODUCTS
         because platform-wide incidents affect all monitored products simultaneously.
         Subject to deduplication by incident.id (if present).

      3. Neither present:
         Silent drop. Handles Atlassian test pings and edge-case payloads gracefully.
         No error raised — this is expected behavior for initial webhook registration.

    Deduplication:
      If the event carries a stable ID (component_update.id or incident.id), the
      dedup cache is checked. If the ID was seen before (Atlassian retry), the event
      is discarded silently. If no ID is present (older Atlassian payload version),
      dedup is skipped and the event is always processed unconditionally.

    Output:
      Formatted log line to stdout via logger.info(). Container orchestrators and
      cloud log aggregators ingest stdout from the running process automatically.
    """
    timestamp: str = _get_utc_timestamp()
    product_name: Optional[str] = None
    status_message: Optional[str] = None

    # ── Priority 1: Component-level update ───────────────────────────────────
    if payload.component and payload.component_update:
        component_name: str = payload.component.name

        if not _is_monitored_product(component_name):
            logger.debug(
                f"Skipping component '{component_name}' — not in MONITORED_PRODUCTS. "
                "HTTP 202 was returned to Atlassian; no console output generated."
            )
            return

        # Idempotency check using the stable Atlassian event UUID
        event_id: Optional[str] = payload.component_update.id
        if event_id is not None:
            if _is_duplicate_event(event_id):
                logger.debug(
                    f"Duplicate component_update discarded: id={event_id}, "
                    f"component='{component_name}'. "
                    "Expected behavior on Atlassian retry after transient failure."
                )
                return

        product_name = component_name
        status_message = _normalize_status(payload.component_update.new_status)

    # ── Priority 2: Platform-wide incident ───────────────────────────────────
    elif payload.incident:
        incident_id: Optional[str] = payload.incident.id
        if incident_id is not None:
            if _is_duplicate_event(incident_id):
                logger.debug(
                    f"Duplicate incident discarded: id={incident_id}, "
                    f"name='{payload.incident.name}'. "
                    "Expected behavior on Atlassian retry after transient failure."
                )
                return

        product_name = "Platform Incident"
        incident_title: str = payload.incident.name
        incident_phase: str = _normalize_status(payload.incident.status)
        status_message = f"{incident_title} - {incident_phase}"

    # ── Priority 3: No actionable data (test ping, empty payload) ────────────
    else:
        logger.debug(
            "Payload contained no component_update or incident data. "
            "Silently dropped. Expected for Atlassian test pings on registration."
        )
        return

    # ── Compose and emit the required output format ───────────────────────────
    # The trailing \n in the format string, combined with the logging module's own
    # newline, produces the required blank separator line between log entries.
    output_line: str = (
        f"{timestamp} Product: {product_name}\n"
        f"Status: {status_message}\n"
    )

    logger.info(output_line)




# ── Test Helpers ──────────────────────────────────────────────────────────────

def reset_dedup_cache_for_tests() -> None:
    """
    Reset dedup structures for tests.

    MUST be called before each test that validates deduplication behavior.
    Without this, test execution order affects results (flaky tests).
    """
    with _dedup_lock:
        _seen_event_ids.clear()
        _seen_event_ids_order.clear()
