"""
Alert Events Threshold Trigger for Sekoia.io

This trigger monitors alert updates in real-time via LiveAPI WebSocket and triggers
playbooks when event accumulation thresholds are met.
"""

import asyncio
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional, cast

from aiohttp import ClientSession, ClientError, ClientTimeout
from pydantic import BaseModel, Field, model_validator
from sekoia_automation.trigger import Trigger

from .helpers.state_manager import AlertStateManager
from .metrics import EVENTS_FORWARDED, EVENTS_FILTERED, THRESHOLD_CHECKS, STATE_SIZE

# Constants
RESTART_DELAY_SECONDS = 60
RETRY_DELAY_SECONDS = 5
MAX_RETRY_ATTEMPTS = 3
REQUEST_TIMEOUT_SECONDS = 30
WEBSOCKET_PING_INTERVAL = 30
WEBSOCKET_PING_TIMEOUT = 10

# Allow test runtime to override the symphony directory
SYMPHONY_DIR = Path(os.environ.get("SEKOIAIO_MODULE_DIR", "/symphony"))


class AlertEventsThresholdConfiguration(BaseModel):
    """
    Configuration for the Alert Events Threshold Trigger.
    """

    # Internal parameters (injected by backend, not exposed to users)
    base_url: str = Field(
        default="",
        description="[INTERNAL] Sekoia.io API base URL (automatically provided)",
        exclude=True,
    )

    api_key: str = Field(
        default="",
        description="[INTERNAL] API key for authentication (automatically provided)",
        json_schema_extra={"secret": True},
        exclude=True,
    )

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

    state_cleanup_days: int = Field(
        default=30,
        ge=1,
        le=365,
        description="Remove state entries for alerts older than N days",
    )

    @model_validator(mode="after")
    def validate_at_least_one_threshold(self):
        """Ensure at least one threshold is enabled."""
        if not self.enable_volume_threshold and not self.enable_time_threshold:
            raise ValueError("At least one threshold must be enabled")
        return self

    @model_validator(mode="after")
    def validate_configuration_consistency(self):
        """Validate configuration parameter relationships."""
        # Both filters set is confusing
        if self.rule_filter and self.rule_names_filter:
            raise ValueError("Use either rule_filter OR rule_names_filter, not both")

        # Cleanup should be longer than time window
        if self.state_cleanup_days * 24 < self.time_window_hours:
            raise ValueError("state_cleanup_days must be longer than time_window_hours")

        return self


class AlertEventsThresholdTrigger(Trigger):
    """
    Trigger that monitors alert updates via LiveAPI WebSocket and triggers playbooks
    when event accumulation thresholds are met.

    This is a Trigger (not a Connector) that:
    - Listens to real-time alert.updated events via WebSocket
    - Detects addition of new events in alerts
    - Applies threshold rules (volume/time)
    - Triggers playbooks via send_event() when thresholds are met
    - Maintains persistent state to avoid duplicate triggers
    """

    configuration: AlertEventsThresholdConfiguration

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state_manager: Optional[AlertStateManager] = None
        self.session: Optional[ClientSession] = None
        self._last_cleanup: Optional[datetime] = None
        self._websocket: Optional[Any] = None

        # Data path: prefer environment override for tests
        self._data_path = Path(os.environ.get("SEKOIAIO_MODULE_DIR", SYMPHONY_DIR)) / "data"

        # Load internal credentials from module context (injected by backend)
        try:
            cfg = getattr(self.module, "configuration", None)
            if cfg is not None:
                self._api_url = getattr(cfg, "base_url", os.environ.get("SEKOIAIO_API_URL", ""))
                self._api_key = getattr(cfg, "api_key", os.environ.get("SEKOIAIO_API_KEY", ""))
            else:
                self._api_url = os.environ.get("SEKOIAIO_API_URL", "")
                self._api_key = os.environ.get("SEKOIAIO_API_KEY", "")
        except Exception:
            # Defensive fallback for tests
            self._api_url = os.environ.get("SEKOIAIO_API_URL", "")
            self._api_key = os.environ.get("SEKOIAIO_API_KEY", "")

    @property
    def alert_api_url(self) -> str:
        """Construct Alert API base URL."""
        return f"{self._api_url}/v1/sic/alerts"

    @property
    def event_api_url(self) -> str:
        """Construct Event API base URL."""
        return f"{self._api_url}/v2/events"

    @property
    def websocket_url(self) -> str:
        """Construct LiveAPI WebSocket URL."""
        base = self._api_url.replace("https://", "wss://").replace("http://", "ws://")
        return f"{base}/live"

    async def _init_session(self) -> None:
        """Initialize HTTP session with authentication headers and timeout."""
        if self.session is None:
            headers = {
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            }
            timeout = ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
            self.session = ClientSession(headers=headers, timeout=timeout)

    async def _close_session(self) -> None:
        """Close HTTP session."""
        if self.session is not None:
            try:
                await self.session.close()
            finally:
                self.session = None

    async def _connect_websocket(self) -> Any:
        """
        Connect to LiveAPI WebSocket with authentication.

        Returns:
            WebSocket connection object
        """
        import aiohttp

        await self._init_session()
        assert self.session is not None

        # WebSocket connection with cookie authentication
        cookie = f"access_token_cookie={self._api_key}"
        headers = {"Cookie": cookie}

        self.log(message="Connecting to LiveAPI WebSocket...", level="info")

        try:
            # Create WebSocket-specific timeout
            ws_timeout = aiohttp.ClientWSTimeout(
                ws_close=WEBSOCKET_PING_TIMEOUT,
                ws_receive=WEBSOCKET_PING_TIMEOUT,
            )

            ws = await self.session.ws_connect(
                self.websocket_url,
                headers=headers,
                heartbeat=WEBSOCKET_PING_INTERVAL,
                timeout=ws_timeout,
            )

            self.log(message="Connected to LiveAPI WebSocket", level="info")
            return ws

        except Exception as e:
            self.log_exception(e, message="Failed to connect to LiveAPI WebSocket")
            raise

    async def _close_websocket(self) -> None:
        """Close WebSocket connection."""
        if self._websocket is not None:
            try:
                await self._websocket.close()
            finally:
                self._websocket = None

    async def _retrieve_alert_from_alertapi(self, alert_uuid: str) -> dict[str, Any]:
        """
        Retrieve full alert details from Alert API with retry logic.

        Args:
            alert_uuid: UUID of the alert

        Returns:
            Alert data dictionary

        Raises:
            ClientError: If retrieval fails after retries
            ValueError: If response format is invalid
        """
        await self._init_session()
        assert self.session is not None

        url = f"{self.alert_api_url}/{alert_uuid}"
        params = {
            "stix": "false",
            "comments": "false",
            "countermeasures": "false",
            "history": "false",
        }

        last_error: Optional[BaseException] = None

        for attempt in range(MAX_RETRY_ATTEMPTS):
            try:
                async with self.session.get(url, params=params) as response:
                    response.raise_for_status()
                    data = await response.json()

                    # Validate response structure
                    if not isinstance(data, dict) or "uuid" not in data:
                        raise ValueError(f"Invalid alert response format: {data}")

                    return data

            except ClientError as e:
                last_error = e
                if attempt < MAX_RETRY_ATTEMPTS - 1:
                    self.log(
                        message=f"Failed to retrieve alert {alert_uuid} (attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS}): {e}",
                        level="warning",
                    )
                    await asyncio.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
                else:
                    self.log_exception(
                        e,
                        message=f"Failed to retrieve alert {alert_uuid} after {MAX_RETRY_ATTEMPTS} attempts",
                    )
                    raise

            except ValueError as e:
                self.log_exception(e, message=f"Invalid alert response for {alert_uuid}")
                raise

        raise last_error if last_error else RuntimeError("Unexpected error in alert retrieval")

    async def _count_events_in_time_window(
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
            Number of events in time window
        """
        await self._init_session()
        assert self.session is not None

        earliest_time = datetime.now(timezone.utc) - timedelta(hours=hours)

        url = f"{self.event_api_url}/search"
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
            async with self.session.post(url, json=payload) as response:
                response.raise_for_status()
                data = await response.json()

                if not isinstance(data, dict):
                    self.log(
                        message=f"Invalid event search response for alert {alert_uuid}: {data}",
                        level="warning",
                    )
                    return 0

                return int(data.get("total", 0))

        except ClientError as e:
            self.log(
                message=f"Failed to count events for alert {alert_uuid}: {e}",
                level="warning",
            )
            return 0  # Fail open

    def _matches_rule_filter(self, alert: dict[str, Any]) -> bool:
        """
        Check if alert matches configured rule filters.

        Args:
            alert: Alert data dictionary

        Returns:
            True if alert matches filters, False otherwise
        """
        rule_name = alert.get("rule", {}).get("name")
        rule_uuid = alert.get("rule", {}).get("uuid")

        # Single rule filter (name or UUID)
        if self.configuration.rule_filter:
            if rule_name == self.configuration.rule_filter:
                return True
            if rule_uuid == self.configuration.rule_filter:
                return True
            return False

        # Multiple rule names filter
        if self.configuration.rule_names_filter:
            return rule_name in self.configuration.rule_names_filter

        # No filters configured: accept all
        return True

    async def _evaluate_thresholds(
        self,
        alert: dict[str, Any],
        previous_state: Optional[dict[str, Any]],
    ) -> tuple[bool, dict[str, Any]]:
        """
        Evaluate whether alert meets triggering thresholds.

        Args:
            alert: Alert data dictionary
            previous_state: Previous state for this alert (if any)

        Returns:
            Tuple of (should_trigger, context_dict)
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
            return False, {}

        trigger_reasons: list[str] = []

        # Volume-based threshold
        if self.configuration.enable_volume_threshold:
            if new_events >= self.configuration.event_count_threshold:
                trigger_reasons.append("volume_threshold")

        # Time-based threshold
        if self.configuration.enable_time_threshold:
            events_in_window = await self._count_events_in_time_window(
                alert_uuid,
                self.configuration.time_window_hours,
            )
            if events_in_window > 0:
                trigger_reasons.append("time_threshold")

        should_trigger = len(trigger_reasons) > 0

        context = {
            "reason": ", ".join(trigger_reasons) if trigger_reasons else "no_threshold_met",
            "new_events": new_events,
            "previous_count": previous_count,
            "current_count": current_event_count,
            "time_window_hours": self.configuration.time_window_hours,
        }

        THRESHOLD_CHECKS.labels(
            triggered="true" if should_trigger else "false",
        ).inc()

        return should_trigger, context

    async def _process_alert_update(self, notification: dict[str, Any]) -> None:
        """
        Process a single alert.updated notification.

        Args:
            notification: WebSocket notification payload
        """
        if not isinstance(notification, dict):
            self.log(
                message=f"Invalid notification format (expected dict): {type(notification)}",
                level="warning",
            )
            return

        # Extract alert info from notification
        alert_data = notification.get("alert", {})
        alert_uuid = alert_data.get("uuid")

        if not alert_uuid:
            self.log(message="Notification missing alert UUID", level="warning")
            return

        try:
            # Retrieve full alert details from Alert API
            alert = await self._retrieve_alert_from_alertapi(alert_uuid)

            # Apply rule filters
            if not self._matches_rule_filter(alert):
                EVENTS_FILTERED.labels(reason="rule_filter").inc()
                return

            # Ensure state manager is initialized
            assert self.state_manager is not None, "state_manager must be initialized"

            # Load previous state
            previous_state = self.state_manager.get_alert_state(alert_uuid)

            # Evaluate thresholds
            should_trigger, context = await self._evaluate_thresholds(
                alert,
                previous_state,
            )

            if not should_trigger:
                EVENTS_FILTERED.labels(reason="threshold_not_met").inc()
                self.log(
                    message=f"Alert {alert.get('short_id')} does not meet thresholds: {context.get('reason', 'unknown')}",
                    level="debug",
                )
                return

            # Update state before triggering
            alert_short_id = cast(str, alert.get("short_id") or "")

            self.state_manager.update_alert_state(
                alert_uuid=alert_uuid,
                alert_short_id=alert_short_id,
                rule_uuid=alert.get("rule", {}).get("uuid") or "",
                rule_name=alert.get("rule", {}).get("name") or "",
                event_count=alert.get("events_count", 0),
                previous_version=previous_state.get("version") if previous_state else None,
            )

            # Construct playbook trigger payload
            payload = {
                "alert": alert,
                "trigger_context": {
                    "triggered_at": datetime.now(timezone.utc).isoformat(),
                    "trigger_type": "alert_events_threshold",
                    **context,
                },
            }

            # Trigger playbook via Trigger.send_event()
            self.send_event(
                event_name=f"Sekoia.io Alert: {alert.get('short_id')}",
                event=payload,
            )

            EVENTS_FORWARDED.labels(
                reason=context["reason"],
            ).inc()

            self.log(
                message=f"Triggered playbook for alert {alert.get('short_id')}: "
                f"{context['new_events']} new events ({context['reason']})",
                level="info",
            )

        except ValueError as e:
            self.log_exception(
                e,
                message=f"Validation error processing alert {alert_uuid}",
            )
        except Exception as e:
            self.log_exception(
                e,
                message=f"Error processing alert {alert_uuid}",
            )

    async def _cleanup_old_states(self) -> None:
        """Periodically clean up state entries for old alerts."""
        now = datetime.now(timezone.utc)

        # Only run once per day
        if self._last_cleanup and (now - self._last_cleanup).total_seconds() < 86400:
            return

        cutoff_date = now - timedelta(days=self.configuration.state_cleanup_days)

        assert self.state_manager is not None, "state_manager must be initialized"
        removed = self.state_manager.cleanup_old_states(cutoff_date)

        # Update metrics
        try:
            STATE_SIZE.set(len(self.state_manager._state["alerts"]))
        except Exception:
            STATE_SIZE.set(0)

        self.log(
            message=f"State cleanup: removed {removed} entries older than "
            f"{self.configuration.state_cleanup_days} days",
            level="info",
        )

        self._last_cleanup = now

    async def _listen_websocket(self) -> None:
        """
        Main WebSocket listener loop.

        Connects to LiveAPI WebSocket, filters for alert.updated events,
        and processes them via _process_alert_update().
        """
        import aiohttp

        retry_count = 0
        max_retries = 10

        while self.running:
            try:
                # Connect to WebSocket
                self._websocket = await self._connect_websocket()
                retry_count = 0  # Reset on successful connection

                # Listen for messages
                async for msg in self._websocket:
                    if msg.type == aiohttp.WSMsgType.TEXT:
                        try:
                            data = msg.json()

                            # Filter for alert.updated events
                            if data.get("event") == "alert.updated":
                                await self._cleanup_old_states()
                                await self._process_alert_update(data)

                        except Exception as e:
                            self.log_exception(
                                e,
                                message="Error processing WebSocket message",
                            )

                    elif msg.type == aiohttp.WSMsgType.ERROR:
                        self.log(
                            message=f"WebSocket error: {self._websocket.exception()}",
                            level="error",
                        )
                        break

                    elif msg.type == aiohttp.WSMsgType.CLOSED:
                        self.log(message="WebSocket closed", level="warning")
                        break

            except asyncio.CancelledError:
                self.log(message="WebSocket listener cancelled", level="info")
                break

            except Exception as e:
                retry_count += 1

                if retry_count > max_retries:
                    self.log_exception(
                        e,
                        message=f"Failed to maintain WebSocket after {max_retries} retries",
                    )
                    raise

                backoff_delay = min(RETRY_DELAY_SECONDS * (2**retry_count), 300)

                self.log(
                    message=f"WebSocket disconnected (attempt {retry_count}/{max_retries}): {e}. "
                    f"Reconnecting in {backoff_delay}s...",
                    level="warning",
                )

                await asyncio.sleep(backoff_delay)

            finally:
                await self._close_websocket()

    def run(self) -> None:
        """
        Main entry point for the trigger (called by Sekoia.io runtime).

        Initializes state manager, connects to WebSocket, and processes events.
        """
        # Initialize state manager
        state_path = self._data_path / "alert_thresholds_state.json"
        self.state_manager = AlertStateManager(state_path, logger=self.log)

        self.log(message="AlertEventsThresholdTrigger started", level="info")

        # Run async WebSocket listener
        try:
            asyncio.run(self._listen_websocket())
        except KeyboardInterrupt:
            self.log(message="Trigger interrupted by user", level="info")
        except Exception as e:
            self.log_exception(e, message="Fatal error in trigger")
        finally:
            # Cleanup
            try:
                asyncio.run(self._close_session())
            except Exception:
                pass

            self.log(message="AlertEventsThresholdTrigger stopped", level="info")
