import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sekoiaio.triggers.alert_events_threshold import (
    AlertEventsThresholdTrigger,
    AlertEventsThresholdConfiguration,
)
from sekoiaio.triggers.helpers.state_manager import AlertStateManager


@pytest.fixture
def mock_module():
    """Create a mock module with configuration."""
    module = MagicMock()
    module.configuration = {
        "base_url": "https://app.sekoia.io",
        "api_key": "test-api-key-12345",
    }
    return module


@pytest.fixture
def sample_alert():
    """Create a sample alert for testing."""
    return {
        "uuid": "alert-uuid-1234",
        "short_id": "ALT-12345",
        "events_count": 150,
        "status": {
            "name": "Ongoing",
            "uuid": "status-uuid",
        },
        "rule": {
            "uuid": "rule-uuid-abcd",
            "name": "Suspicious PowerShell Activity",
        },
        "urgency": {
            "current_value": 70,
        },
        "entity": {
            "uuid": "entity-uuid",
            "name": "Test Entity",
        },
        "alert_type": {
            "value": "malware",
        },
        "created_at": "2025-11-14T08:00:00.000000Z",
        "updated_at": "2025-11-14T10:30:00.000000Z",
        "first_seen_at": "2025-11-14T08:00:00.000000Z",
        "last_seen_at": "2025-11-14T10:30:00.000000Z",
    }


@pytest.fixture
def trigger(mock_module, tmp_path):
    """Create a trigger instance with mocked dependencies."""
    trigger = AlertEventsThresholdTrigger()
    trigger.module = mock_module
    trigger.configuration = {
        "event_count_threshold": 100,
        "time_window_hours": 1,
        "enable_volume_threshold": True,
        "enable_time_threshold": True,
        "check_interval_seconds": 60,
        "state_cleanup_days": 30,
    }
    trigger._data_path = tmp_path
    trigger.log = MagicMock()
    trigger.log_exception = MagicMock()
    trigger.send_event = MagicMock()

    return trigger


class TestAlertEventsThresholdConfiguration:
    """Test configuration validation."""

    def test_valid_configuration(self):
        """Test that valid configuration is accepted."""
        config = AlertEventsThresholdConfiguration(
            event_count_threshold=100,
            time_window_hours=1,
            enable_volume_threshold=True,
            enable_time_threshold=True,
        )
        assert config.event_count_threshold == 100
        assert config.time_window_hours == 1

    def test_at_least_one_threshold_required(self):
        """Test that at least one threshold must be enabled."""
        with pytest.raises(ValueError, match="At least one threshold must be enabled"):
            AlertEventsThresholdConfiguration(
                enable_volume_threshold=False,
                enable_time_threshold=False,
            )

    def test_cannot_use_both_filters(self):
        """Test that both rule filters cannot be used simultaneously."""
        with pytest.raises(ValueError, match="Use either rule_filter OR rule_names_filter"):
            AlertEventsThresholdConfiguration(
                rule_filter="Test Rule",
                rule_names_filter=["Rule 1", "Rule 2"],
            )


class TestAlertEventsThresholdTrigger:
    """Test trigger logic."""

    def test_first_occurrence_triggers_immediately(self, trigger, sample_alert):
        """Test that first occurrence of an alert triggers immediately."""
        # Initialize state manager
        trigger._ensure_initialized()

        # Evaluate thresholds for first occurrence (no previous state)
        should_trigger, context = trigger._evaluate_thresholds(sample_alert, previous_state=None)

        assert should_trigger is True
        assert context["reason"] == "first_occurrence"
        assert context["new_events"] == 150
        assert context["previous_count"] == 0

    def test_volume_threshold_triggers(self, trigger, sample_alert):
        """Test that volume threshold triggers correctly."""
        # Initialize state manager
        trigger._ensure_initialized()

        # Create previous state with 50 events
        previous_state = {
            "last_triggered_event_count": 50,
            "version": 1,
        }

        # Current alert has 150 events (100 new events)
        sample_alert["events_count"] = 150

        # Mock time-based check to return 0 (disable time threshold for this test)
        with patch.object(trigger, '_count_events_in_time_window', return_value=0):
            should_trigger, context = trigger._evaluate_thresholds(sample_alert, previous_state)

        assert should_trigger is True
        assert "volume_threshold" in context["reason"]
        assert context["new_events"] == 100

    def test_below_threshold_does_not_trigger(self, trigger, sample_alert):
        """Test that alerts below threshold do not trigger."""
        # Disable time threshold for this test
        trigger.configuration["enable_time_threshold"] = False

        # Initialize state manager
        trigger._ensure_initialized()

        # Create previous state with 100 events
        previous_state = {
            "last_triggered_event_count": 100,
            "version": 1,
        }

        # Current alert has 150 events (50 new events, below 100 threshold)
        sample_alert["events_count"] = 150

        should_trigger, context = trigger._evaluate_thresholds(sample_alert, previous_state)

        assert should_trigger is False
        assert context["reason"] == "no_threshold_met"

    def test_no_new_events_does_not_trigger(self, trigger, sample_alert):
        """Test that alerts with no new events do not trigger."""
        # Initialize state manager
        trigger._ensure_initialized()

        # Create previous state with 150 events
        previous_state = {
            "last_triggered_event_count": 150,
            "version": 1,
        }

        # Current alert has same 150 events
        sample_alert["events_count"] = 150

        should_trigger, context = trigger._evaluate_thresholds(sample_alert, previous_state)

        assert should_trigger is False
        assert context["reason"] == "no_new_events"

    def test_rule_filter_matches_name(self, trigger, sample_alert):
        """Test that rule filter matches by name."""
        trigger.configuration["rule_filter"] = "Suspicious PowerShell Activity"

        matches = trigger._should_process_alert(sample_alert)
        assert matches is True

    def test_rule_filter_matches_uuid(self, trigger, sample_alert):
        """Test that rule filter matches by UUID."""
        trigger.configuration["rule_filter"] = "rule-uuid-abcd"

        matches = trigger._should_process_alert(sample_alert)
        assert matches is True

    def test_rule_filter_blocks_non_matching(self, trigger, sample_alert):
        """Test that rule filter blocks non-matching alerts."""
        trigger.configuration["rule_filter"] = "Different Rule Name"

        matches = trigger._should_process_alert(sample_alert)
        assert matches is False

    def test_handle_event_with_mocked_api(self, trigger, sample_alert):
        """Test the event handling with mocked API calls."""
        # Setup notification message
        message = {
            "type": "alert",
            "action": "updated",
            "attributes": {
                "uuid": "alert-uuid-1234",
            },
        }

        # Mock the API calls
        with patch.object(trigger, '_retrieve_alert_from_alertapi', return_value=sample_alert):
            with patch.object(trigger, '_count_events_in_time_window', return_value=10):
                # Handle the event
                trigger.handle_event(message)

                # Verify that send_event was called (first occurrence triggers)
                assert trigger.send_event.called


class TestStateManager:
    """Test state manager functionality."""

    def test_get_nonexistent_alert_returns_none(self, tmp_path):
        """Test that getting a non-existent alert returns None."""
        state_path = tmp_path / "test_state.json"
        manager = AlertStateManager(state_path)

        state = manager.get_alert_state("nonexistent-uuid")
        assert state is None

    def test_update_alert_state_creates_new(self, tmp_path):
        """Test creating a new alert state."""
        state_path = tmp_path / "test_state.json"
        manager = AlertStateManager(state_path)

        manager.update_alert_state(
            alert_uuid="test-uuid",
            alert_short_id="ALT-99999",
            rule_uuid="rule-uuid",
            rule_name="Test Rule",
            event_count=50,
        )

        state = manager.get_alert_state("test-uuid")
        assert state is not None
        assert state["alert_short_id"] == "ALT-99999"
        assert state["last_triggered_event_count"] == 50
        assert state["total_triggers"] == 1

    def test_update_alert_state_increments_triggers(self, tmp_path):
        """Test that updating state increments trigger count."""
        state_path = tmp_path / "test_state.json"
        manager = AlertStateManager(state_path)

        # First update
        manager.update_alert_state(
            alert_uuid="test-uuid",
            alert_short_id="ALT-99999",
            rule_uuid="rule-uuid",
            rule_name="Test Rule",
            event_count=50,
        )

        # Second update
        manager.update_alert_state(
            alert_uuid="test-uuid",
            alert_short_id="ALT-99999",
            rule_uuid="rule-uuid",
            rule_name="Test Rule",
            event_count=150,
        )

        state = manager.get_alert_state("test-uuid")
        assert state["last_triggered_event_count"] == 150
        assert state["total_triggers"] == 2

    def test_cleanup_old_states(self, tmp_path):
        """Test cleanup of old alert states."""
        state_path = tmp_path / "test_state.json"
        manager = AlertStateManager(state_path)

        now = datetime.now(timezone.utc)

        # Create old alert (60 days ago)
        manager._state["alerts"]["old-alert"] = {
            "alert_uuid": "old-alert",
            "last_triggered_at": (now - timedelta(days=60)).isoformat(),
            "last_triggered_event_count": 100,
        }
        manager._save_state()

        # Create recent alert
        manager.update_alert_state(
            alert_uuid="recent-alert",
            alert_short_id="ALT-11111",
            rule_uuid="rule-uuid",
            rule_name="Recent Rule",
            event_count=50,
        )

        # Cleanup entries older than 30 days
        cutoff = now - timedelta(days=30)
        removed = manager.cleanup_old_states(cutoff)

        assert removed == 1
        assert manager.get_alert_state("old-alert") is None
        assert manager.get_alert_state("recent-alert") is not None
