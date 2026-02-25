"""
models.py — Pydantic v2 Data Contracts for Atlassian Statuspage Webhook Payloads

Atlassian Statuspage emits two structurally distinct payload morphologies:

  1. Component Update: both `component` and `component_update` objects are present.
     The `component.name` is the affected product. The `component_update.new_status`
     is the operational state transition (e.g., "degraded_performance").

  2. Platform Incident: the `incident` object is present.
     The `incident.name` is the outage title. The `incident.status` is the phase
     (e.g., "investigating", "identified", "monitoring", "resolved").

Both morphologies are captured by the single `WebhookPayload` model using Optional fields.
All unknown and irrelevant fields (unsubscribe_href, postmortem_body, page metadata, etc.)
are silently dropped via `model_config = ConfigDict(extra='ignore')`. This ensures the
application remains resilient to Atlassian adding new fields to their payload schema.

Design rules:
- Required fields use bare type annotations (e.g., `name: str`)
- Optional fields use `Optional[X] = None` explicitly
- All models carry ConfigDict(extra='ignore') — never fail on unknown fields

Change log:
  v2.1 — Added `id` field to ComponentUpdate and Incident models.
         Atlassian includes a stable UUID per event. This ID is consumed by
         processor.py to detect and discard duplicate deliveries from Atlassian
         retries after transient network failures or 5xx responses.
"""

from typing import Optional
from pydantic import BaseModel, ConfigDict


class Component(BaseModel):
    """Represents the affected service component in a component-level update event."""

    model_config = ConfigDict(extra='ignore')

    name: str                          # Required: product identifier, e.g. "OpenAI API"
    status: Optional[str] = None       # Current status snapshot (may differ from update)
    id: Optional[str] = None           # Atlassian component UUID
    description: Optional[str] = None  # Human-readable component description


class ComponentUpdate(BaseModel):
    """Represents the state transition event for a single component."""

    model_config = ConfigDict(extra='ignore')

    new_status: str                    # REQUIRED — this IS the event. Fail without it.
    old_status: Optional[str] = None   # Previous state (useful for change detection)
    created_at: Optional[str] = None   # ISO 8601 timestamp of the state change
    id: Optional[str] = None           # Atlassian event UUID — used for deduplication.
                                       # Prevents duplicate log entries when Atlassian
                                       # retries delivery after a transient failure.


class IncidentUpdate(BaseModel):
    """A single chronological update message within an incident timeline."""

    model_config = ConfigDict(extra='ignore')

    body: Optional[str] = None         # Human-readable update message
    status: Optional[str] = None       # Phase at time of this update
    created_at: Optional[str] = None   # ISO 8601 timestamp of this update


class Incident(BaseModel):
    """Represents a platform-wide incident declaration."""

    model_config = ConfigDict(extra='ignore')

    name: str                                                # REQUIRED: incident title
    status: str                                              # REQUIRED: current phase
    id: Optional[str] = None                                 # Atlassian incident UUID.
                                                             # Used for deduplication
                                                             # on retry deliveries.
    impact: Optional[str] = None                             # Scope: none/minor/major/critical
    incident_updates: Optional[list[IncidentUpdate]] = None  # Chronological update log
    shortlink: Optional[str] = None                          # Public status page link


class WebhookPayload(BaseModel):
    """
    Master webhook payload model — handles all Atlassian Statuspage event types.

    All top-level fields are Optional because Atlassian may send payloads containing
    only `component`+`component_update`, only `incident`, or (for test pings) neither.
    The processor handles all three cases explicitly via priority logic.

    The `page` field captures page-level metadata for completeness but is not
    processed by the business logic layer.
    """

    model_config = ConfigDict(extra='ignore')

    component: Optional[Component] = None
    component_update: Optional[ComponentUpdate] = None
    incident: Optional[Incident] = None
    page: Optional[dict] = None  # Page-level metadata — captured, not processed
