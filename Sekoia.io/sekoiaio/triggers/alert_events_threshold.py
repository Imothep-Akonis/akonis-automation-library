import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from posixpath import join as urljoin
from typing import Any, Optional

import orjson
import requests
from pydantic import BaseModel, Field, model_validator

from sekoiaio.utils import user_agent
from .alerts import SecurityAlertsTrigger
from .helpers.state_manager import AlertStateManager
from .metrics import EVENTS_FORWARDED, EVENTS_FILTERED, THRESHOLD_CHECKS, STATE_SIZE


class AlertEventsThresholdConfiguration(BaseModel):
    """
    Configuration for the Alert Events Threshold Trigger.
    """

    # User-configurable parameters
    rule_filter: Optional[str] = Field(
        None,
        description="Filter by rule name or UUID (single rule only)",
    )

    rule_names_filter: list[str] = Field(
        default_factory=list,
        description="Filter by multiple rule names",
    )

    event_count_threshold: int = Field(
        default=100,
        ge=1,
        description="Minimum number of new events to trigger (volume-based)",
    )

    time_window_hours: int = Field(
        default=1,
        ge=1,
        le=168,
        description="Time window in hours for time-based triggering (max 7 days)",
    )

    enable_volume_threshold: bool = Field(
        default=True,
        description="Enable volume-based threshold (>= N events)",
    )

    enable_time_threshold: bool = Field(
        default=True,
        description="Enable time-based threshold (activity in last N hours)",
    )

    check_interval_seconds: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Polling interval for checking thresholds (10s - 1h)",
    )

    state_cleanup_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Remove state entries for alerts older than N days",
    )

    @model_validator(mode='after')
    def validate_at_least_one_threshold(self):
        """Ensure at least one threshold is enabled."""
        if not self.enable_volume_threshold and not self.enable_time_threshold:
            raise ValueError("At least one threshold must be enabled")
        return self

    @model_validator(mode='after')
    def validate_configuration_consistency(self):
        """Validate configuration parameter relationships."""
        # Both filters set is confusing
        if self.rule_filter and self.rule_names_filter:
            raise ValueError("Use either rule_filter OR rule_names_filter, not both")

        # Cleanup should be longer than time window
        if self.state_cleanup_days * 24 < self.time_window_hours:
            raise ValueError("state_cleanup_days must be longer than time_window_hours")

        return self


class AlertEventsThresholdTrigger(SecurityAlertsTrigger):
    """
    Trigger that monitors alert updates and triggers playbooks only when
    event accumulation thresholds are met.

    Supports dual threshold logic:
    - Volume-based: Trigger if >= N new events added
    - Time-based: Trigger if >= 1 event added in last N hours

    This trigger extends SecurityAlertsTrigger to reuse common alert handling logic
    like API retrieval and rule filtering.
    """

    # Handle only alert updates
    HANDLED_EVENT_SUB_TYPES = [("alert", "updated")]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state_manager: Optional[AlertStateManager] = None
        self._last_cleanup: Optional[datetime] = None
        self._initialized = False

    def _ensure_initialized(self):
        """Lazy initialization of state manager."""
        if not self._initialized:
            state_path = self._data_path / "alert_thresholds_state.json"
            self.state_manager = AlertStateManager(state_path, logger=self.log)
            self._initialized = True
            self.log(message="AlertEventsThresholdTrigger initialized", level="info")

    def handle_event(self, message):
        """
        Handle alert update messages with threshold evaluation.

        This method overrides the parent class to add threshold logic before
        triggering the playbook.
        """
        # Ensure state manager is initialized
        self._ensure_initialized()

        alert_attrs = message.get("attributes", {})
        event_type: str = message.get("type", "")
        event_action: str = message.get("action", "")

        # Only handle alert updates
        if (event_type, event_action) not in self.HANDLED_EVENT_SUB_TYPES:
            return

        # Extract alert UUID
        alert_uuid: str = alert_attrs.get("uuid", "")
        if not alert_uuid:
            self.log(message="Notification missing alert UUID", level="warning")
            return

        try:
            # ✨ Reuse parent's method for API retrieval
            alert = self._retrieve_alert_from_alertapi(alert_uuid)
        except Exception as exp:
            self.log_exception(exp, message="Failed to fetch alert from Alert API")
            return

        # ✨ Reuse parent's rule filtering logic
        if not self._should_process_alert(alert):
            EVENTS_FILTERED.labels(reason="rule_filter").inc()
            return

        # Load previous state for this alert
        previous_state = self.state_manager.get_alert_state(alert_uuid)

        # Evaluate thresholds
        should_trigger, context = self._evaluate_thresholds(alert, previous_state)

        if not should_trigger:
            EVENTS_FILTERED.labels(reason="threshold_not_met").inc()
            self.log(
                message=f"Alert {alert.get('short_id')} does not meet thresholds: {context.get('reason', 'unknown')}",
                level="debug",
            )
            return

        # Update state before triggering
        self.state_manager.update_alert_state(
            alert_uuid=alert_uuid,
            alert_short_id=alert.get("short_id"),
            rule_uuid=alert.get("rule", {}).get("uuid"),
            rule_name=alert.get("rule", {}).get("name"),
            event_count=alert.get("events_count", 0),
            previous_version=previous_state.get("version") if previous_state else None,
        )

        # Periodic cleanup of old states
        self._cleanup_old_states()

        # ✨ Reuse parent's method for creating event payload
        self._send_threshold_event(alert, event_type, context)

        EVENTS_FORWARDED.labels(reason=context["reason"]).inc()

        self.log(
            message=f"Triggered for alert {alert.get('short_id')}: {context['new_events']} new events ({context['reason']})",
            level="info",
        )

    def _should_process_alert(self, alert: dict[str, Any]) -> bool:
        """
        Check if alert should be processed based on rule filters.

        This reuses the parent class logic for consistency.

        Args:
            alert: Alert data dictionary

        Returns:
            True if alert matches filters (or no filters configured)
        """
        rule_filter = self.configuration.get("rule_filter")
        rule_names_filter = self.configuration.get("rule_names_filter")

        # No filters: accept all
        if not rule_filter and not rule_names_filter:
            return True

        rule_name = alert.get("rule", {}).get("name")
        rule_uuid = alert.get("rule", {}).get("uuid")

        # Single rule filter
        if rule_filter:
            return rule_name == rule_filter or rule_uuid == rule_filter

        # Multiple rule names filter
        if rule_names_filter:
            return rule_name in rule_names_filter

        return True

    def _send_threshold_event(self, alert: dict[str, Any], event_type: str, context: dict[str, Any]):
        """
        Send event to playbook with threshold context.

        This extends the parent's event creation with threshold-specific information.

        Args:
            alert: Alert data dictionary
            event_type: Type of the event
            context: Threshold evaluation context
        """
        # Create work directory for alert data
        work_dir = self._data_path.joinpath("sekoiaio_alert_threshold").joinpath(str(uuid.uuid4()))
        alert_path = work_dir.joinpath("alert.json")
        work_dir.mkdir(parents=True, exist_ok=True)

        with alert_path.open("w") as fp:
            fp.write(orjson.dumps(alert).decode("utf-8"))

        directory = str(work_dir.relative_to(self._data_path))
        file_path = str(alert_path.relative_to(work_dir))

        alert_short_id = alert.get("short_id")

        # Build event payload (similar to parent but with threshold context)
        event = {
            "file_path": file_path,
            "event_type": event_type,
            "alert_uuid": alert["uuid"],
            "short_id": alert_short_id,
            "status": {
                "name": alert.get("status", {}).get("name"),
                "uuid": alert.get("status", {}).get("uuid"),
            },
            "created_at": alert.get("created_at"),
            "urgency": alert.get("urgency", {}).get("current_value"),
            "entity": alert.get("entity", {}),
            "alert_type": alert.get("alert_type", {}),
            "rule": {"name": alert["rule"]["name"], "uuid": alert["rule"]["uuid"]},
            "last_seen_at": alert.get("last_seen_at"),
            "first_seen_at": alert.get("first_seen_at"),
            "events_count": alert.get("events_count", 0),
            # ✨ Add threshold-specific context
            "trigger_context": {
                "triggered_at": datetime.now(timezone.utc).isoformat(),
                "trigger_type": "alert_events_threshold",
                **context,
            },
        }

        self.send_event(
            event_name=f"Sekoia.io Alert Threshold: {alert_short_id}",
            event=event,
            directory=directory,
            remove_directory=True,
        )

    def _evaluate_thresholds(
        self,
        alert: dict[str, Any],
        previous_state: Optional[dict[str, Any]],
    ) -> tuple[bool, dict[str, Any]]:
        """
        Evaluate whether alert meets triggering thresholds.

        Args:
            alert: Current alert data
            previous_state: Previous state for this alert (if any)

        Returns:
            Tuple of (should_trigger, trigger_context)
        """
        alert_uuid = alert["uuid"]
        current_event_count = alert.get("events_count", 0)

        # First time seeing this alert: trigger immediately
        if previous_state is None:
            context = {
                "reason": "first_occurrence",
                "new_events": current_event_count,
                "previous_count": 0,
                "current_count": current_event_count,
            }
            THRESHOLD_CHECKS.labels(triggered="true").inc()
            return True, context

        previous_count = previous_state.get("last_triggered_event_count", 0)
        new_events = current_event_count - previous_count

        # No new events: skip
        if new_events <= 0:
            THRESHOLD_CHECKS.labels(triggered="false").inc()
            return False, {"reason": "no_new_events"}

        trigger_reasons = []

        # Volume-based threshold
        enable_volume = self.configuration.get("enable_volume_threshold", True)
        event_count_threshold = self.configuration.get("event_count_threshold", 100)

        if enable_volume and new_events >= event_count_threshold:
            trigger_reasons.append("volume_threshold")

        # Time-based threshold
        enable_time = self.configuration.get("enable_time_threshold", True)
        time_window_hours = self.configuration.get("time_window_hours", 1)

        if enable_time:
            events_in_window = self._count_events_in_time_window(
                alert_uuid,
                time_window_hours,
            )
            if events_in_window > 0:
                trigger_reasons.append("time_threshold")

        should_trigger = len(trigger_reasons) > 0

        context = {
            "reason": ", ".join(trigger_reasons) if trigger_reasons else "no_threshold_met",
            "new_events": new_events,
            "previous_count": previous_count,
            "current_count": current_event_count,
            "time_window_hours": time_window_hours,
        }

        THRESHOLD_CHECKS.labels(triggered="true" if should_trigger else "false").inc()

        return should_trigger, context

    def _count_events_in_time_window(
        self,
        alert_uuid: str,
        hours: int,
    ) -> int:
        """
        Count events added to alert within the last N hours.

        Args:
            alert_uuid: UUID of the alert
            hours: Time window in hours

        Returns:
            Number of events in the time window
        """
        earliest_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        api_url = urljoin(self.module.configuration["base_url"], "api/v2/events/search")
        api_url = api_url.replace("/api/api", "/api")

        api_key = self.module.configuration["api_key"]
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": user_agent(),
        }

        payload = {
            "filter": {
                "alert_uuid": alert_uuid,
                "created_at": {
                    "gte": earliest_time.isoformat(),
                },
            },
            "size": 0,  # We only need the count
        }

        try:
            response = requests.post(api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get("total", 0)
        except Exception as e:
            self.log(
                message=f"Failed to count events for alert {alert_uuid}: {e}",
                level="warning",
            )
            return 0  # Fail open: don't block on count errors

    def _cleanup_old_states(self):
        """
        Periodically clean up state entries for old alerts (once per day).
        """
        now = datetime.now(timezone.utc)

        # Only run once per day
        if self._last_cleanup and (now - self._last_cleanup).total_seconds() < 86400:
            return

        state_cleanup_days = self.configuration.get("state_cleanup_days", 30)
        cutoff_date = now - timedelta(days=state_cleanup_days)
        removed = self.state_manager.cleanup_old_states(cutoff_date)

        # Update state size metric
        STATE_SIZE.set(len(self.state_manager._state["alerts"]))

        if removed > 0:
            self.log(
                message=f"State cleanup: removed {removed} entries older than {state_cleanup_days} days",
                level="info",
            )

        self._last_cleanup = now
