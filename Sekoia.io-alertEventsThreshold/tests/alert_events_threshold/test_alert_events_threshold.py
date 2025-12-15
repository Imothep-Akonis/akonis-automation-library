"""
Tests for AlertEventsThresholdTrigger

Tests cover:
- Configuration validation
- WebSocket message processing
- Threshold evaluation logic
- Rule filtering
- State management integration
- Error handling
"""

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from typing import Any
from sekoiaio.triggers.helpers.state_manager import AlertStateManager

import pytest
from aiohttp import WSMsgType

from sekoia_automation.module import Module
from alert_events_threshold import (
    AlertEventsThresholdConfiguration,
    AlertEventsThresholdTrigger,
)


@pytest.fixture
def temp_data_dir(tmp_path):
    """Create temporary data directory for tests."""
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Override environment variable for tests
    os.environ["SEKOIAIO_MODULE_DIR"] = str(tmp_path)
    
    yield data_dir
    
    # Cleanup
    if "SEKOIAIO_MODULE_DIR" in os.environ:
        del os.environ["SEKOIAIO_MODULE_DIR"]


@pytest.fixture
def mock_module():
    """Create mock module with configuration."""
    module = Mock(spec=Module)
    
    # Mock configuration
    cfg = Mock()
    cfg.base_url = "https://api.sekoia.io"
    cfg.api_key = "test_api_key"
    module.configuration = cfg
    
    # Mock has_secrets
    module.has_secrets = Mock(return_value=False)
    
    return module


@pytest.fixture
def valid_config():
    """Valid trigger configuration."""
    return {
        "base_url": "https://api.sekoia.io",
        "api_key": "test_api_key",
        "event_count_threshold": 100,
        "time_window_hours": 1,
        "enable_volume_threshold": True,
        "enable_time_threshold": True,
        "state_cleanup_days": 30,
    }


@pytest.fixture
def trigger(mock_module, valid_config, temp_data_dir):
    """Create trigger instance with mocked dependencies."""
    trigger = AlertEventsThresholdTrigger(module=mock_module, data_path=temp_data_dir)
    
    # Set configuration
    trigger.configuration = AlertEventsThresholdConfiguration(**valid_config)
    
    # Mock logging
    trigger.log = Mock()
    trigger.log_exception = Mock()
    
    # Mock send_event
    trigger.send_event = Mock()
    
    return trigger


class TestConfiguration:
    """Test configuration validation."""

    def test_valid_configuration(self, valid_config):
        """Test valid configuration passes validation."""
        config = AlertEventsThresholdConfiguration(**valid_config)
        assert config.event_count_threshold == 100
        assert config.time_window_hours == 1
        assert config.enable_volume_threshold is True
        assert config.enable_time_threshold is True

    def test_at_least_one_threshold_required(self, valid_config):
        """Test that at least one threshold must be enabled."""
        valid_config["enable_volume_threshold"] = False
        valid_config["enable_time_threshold"] = False
        
        with pytest.raises(ValueError, match="at least one threshold"):
            AlertEventsThresholdConfiguration(**valid_config)

    def test_conflicting_rule_filters(self, valid_config):
        """Test that both rule filters cannot be set simultaneously."""
        valid_config["rule_filter"] = "test_rule"
        valid_config["rule_names_filter"] = ["rule1", "rule2"]
        
        with pytest.raises(ValueError, match="either rule_filter OR rule_names_filter"):
            AlertEventsThresholdConfiguration(**valid_config)

    def test_cleanup_days_validation(self, valid_config):
        """Test that cleanup days must be longer than time window."""
        valid_config["time_window_hours"] = 168  # 7 days
        valid_config["state_cleanup_days"] = 6  # Less than 7 days
        
        with pytest.raises(ValueError, match="state_cleanup_days must be longer"):
            AlertEventsThresholdConfiguration(**valid_config)

    def test_threshold_bounds(self, valid_config):
        """Test threshold parameter bounds."""
        # Test minimum event count
        valid_config["event_count_threshold"] = 0
        with pytest.raises(ValueError):
            AlertEventsThresholdConfiguration(**valid_config)
        
        # Test time window bounds
        valid_config["event_count_threshold"] = 100
        valid_config["time_window_hours"] = 0
        with pytest.raises(ValueError):
            AlertEventsThresholdConfiguration(**valid_config)
        
        valid_config["time_window_hours"] = 200  # > 168 (7 days)
        with pytest.raises(ValueError):
            AlertEventsThresholdConfiguration(**valid_config)


class TestRuleFiltering:
    """Test rule filtering logic."""

    def test_no_filter_accepts_all(self, trigger):
        """Test that alerts pass when no filters are configured."""
        alert = {
            "uuid": "alert-123",
            "rule": {"uuid": "rule-456", "name": "Test Rule"},
        }
        
        assert trigger._matches_rule_filter(alert) is True

    def test_single_rule_filter_by_name(self, trigger):
        """Test filtering by single rule name."""
        trigger.configuration.rule_filter = "Test Rule"
        
        alert_match = {
            "uuid": "alert-123",
            "rule": {"uuid": "rule-456", "name": "Test Rule"},
        }
        
        alert_no_match = {
            "uuid": "alert-789",
            "rule": {"uuid": "rule-999", "name": "Other Rule"},
        }
        
        assert trigger._matches_rule_filter(alert_match) is True
        assert trigger._matches_rule_filter(alert_no_match) is False

    def test_single_rule_filter_by_uuid(self, trigger):
        """Test filtering by single rule UUID."""
        trigger.configuration.rule_filter = "rule-456"
        
        alert_match = {
            "uuid": "alert-123",
            "rule": {"uuid": "rule-456", "name": "Test Rule"},
        }
        
        alert_no_match = {
            "uuid": "alert-789",
            "rule": {"uuid": "rule-999", "name": "Test Rule"},
        }
        
        assert trigger._matches_rule_filter(alert_match) is True
        assert trigger._matches_rule_filter(alert_no_match) is False

    def test_multiple_rule_names_filter(self, trigger):
        """Test filtering by multiple rule names."""
        trigger.configuration.rule_names_filter = ["Rule A", "Rule B"]
        
        alert_match_a = {
            "uuid": "alert-123",
            "rule": {"uuid": "rule-456", "name": "Rule A"},
        }
        
        alert_match_b = {
            "uuid": "alert-789",
            "rule": {"uuid": "rule-999", "name": "Rule B"},
        }
        
        alert_no_match = {
            "uuid": "alert-000",
            "rule": {"uuid": "rule-000", "name": "Rule C"},
        }
        
        assert trigger._matches_rule_filter(alert_match_a) is True
        assert trigger._matches_rule_filter(alert_match_b) is True
        assert trigger._matches_rule_filter(alert_no_match) is False


class TestThresholdEvaluation:
    """Test threshold evaluation logic."""

    @pytest.mark.asyncio
    async def test_first_occurrence_always_triggers(self, trigger):
        """Test that first occurrence of an alert always triggers."""
        alert = {
            "uuid": "alert-123",
            "events_count": 50,
        }
        
        should_trigger, context = await trigger._evaluate_thresholds(alert, None)
        
        assert should_trigger is True
        assert context["reason"] == "first_occurrence"
        assert context["new_events"] == 50
        assert context["previous_count"] == 0

    @pytest.mark.asyncio
    async def test_no_new_events_does_not_trigger(self, trigger):
        """Test that no new events does not trigger."""
        alert = {
            "uuid": "alert-123",
            "events_count": 100,
        }
        
        previous_state = {
            "last_triggered_event_count": 100,
        }
        
        should_trigger, context = await trigger._evaluate_thresholds(
            alert, previous_state
        )
        
        assert should_trigger is False
        assert context == {}

    @pytest.mark.asyncio
    async def test_volume_threshold_met(self, trigger):
        """Test volume threshold triggering."""
        trigger.configuration.event_count_threshold = 100
        trigger.configuration.enable_volume_threshold = True
        trigger.configuration.enable_time_threshold = False
        
        alert = {
            "uuid": "alert-123",
            "events_count": 250,
        }
        
        previous_state = {
            "last_triggered_event_count": 100,
        }
        
        should_trigger, context = await trigger._evaluate_thresholds(
            alert, previous_state
        )
        
        assert should_trigger is True
        assert "volume_threshold" in context["reason"]
        assert context["new_events"] == 150

    @pytest.mark.asyncio
    async def test_volume_threshold_not_met(self, trigger):
        """Test volume threshold not triggering."""
        trigger.configuration.event_count_threshold = 100
        trigger.configuration.enable_volume_threshold = True
        trigger.configuration.enable_time_threshold = False
        
        alert = {
            "uuid": "alert-123",
            "events_count": 150,
        }
        
        previous_state = {
            "last_triggered_event_count": 100,
        }
        
        should_trigger, context = await trigger._evaluate_thresholds(
            alert, previous_state
        )
        
        assert should_trigger is False
        assert context["reason"] == "no_threshold_met"

    @pytest.mark.asyncio
    async def test_time_threshold_met(self, trigger):
        """Test time-based threshold triggering."""
        trigger.configuration.enable_volume_threshold = False
        trigger.configuration.enable_time_threshold = True
        trigger.configuration.time_window_hours = 1
        
        alert = {
            "uuid": "alert-123",
            "events_count": 150,
        }
        
        previous_state = {
            "last_triggered_event_count": 100,
        }
        
        # Mock event counting
        trigger._count_events_in_time_window = AsyncMock(return_value=10)
        
        should_trigger, context = await trigger._evaluate_thresholds(
            alert, previous_state
        )
        
        assert should_trigger is True
        assert "time_threshold" in context["reason"]
        assert context["new_events"] == 50

    @pytest.mark.asyncio
    async def test_both_thresholds_met(self, trigger):
        """Test both volume and time thresholds triggering."""
        trigger.configuration.event_count_threshold = 100
        trigger.configuration.enable_volume_threshold = True
        trigger.configuration.enable_time_threshold = True
        
        alert = {
            "uuid": "alert-123",
            "events_count": 250,
        }
        
        previous_state = {
            "last_triggered_event_count": 100,
        }
        
        # Mock event counting
        trigger._count_events_in_time_window = AsyncMock(return_value=20)
        
        should_trigger, context = await trigger._evaluate_thresholds(
            alert, previous_state
        )
        
        assert should_trigger is True
        assert "volume_threshold" in context["reason"]
        assert "time_threshold" in context["reason"]


class TestAlertProcessing:
    """Test alert update processing."""

    @pytest.mark.asyncio
    async def test_invalid_notification_format(self, trigger):
        """Test handling of invalid notification format."""
        await trigger._process_alert_update("not_a_dict")
        
        trigger.log.assert_called_once()
        assert "Invalid notification format" in str(trigger.log.call_args)

    @pytest.mark.asyncio
    async def test_missing_alert_uuid(self, trigger):
        """Test handling of notification without alert UUID."""
        notification = {"alert": {}}
        
        await trigger._process_alert_update(notification)
        
        trigger.log.assert_called_once()
        assert "missing alert UUID" in str(trigger.log.call_args)

    @pytest.mark.asyncio
    async def test_filtered_by_rule(self, trigger, temp_data_dir):
        """Test alert filtered by rule filter."""

        
        trigger.configuration.rule_filter = "Specific Rule"
        trigger.state_manager = AlertStateManager(
            temp_data_dir / "state.json",
            logger=trigger.log
        )
        
        # Mock API call
        trigger._retrieve_alert_from_alertapi = AsyncMock(return_value={
            "uuid": "alert-123",
            "short_id": "AL-123",
            "events_count": 100,
            "rule": {"uuid": "rule-456", "name": "Other Rule"},
        })
        
        notification = {
            "alert": {"uuid": "alert-123"},
        }
        
        await trigger._process_alert_update(notification)
        
        # Should not trigger send_event
        trigger.send_event.assert_not_called()

    @pytest.mark.asyncio
    async def test_successful_trigger(self, trigger, temp_data_dir):
        """Test successful alert processing and playbook trigger."""

        
        trigger.state_manager = AlertStateManager(
            temp_data_dir / "state.json",
            logger=trigger.log
        )
        
        # Mock API calls
        trigger._retrieve_alert_from_alertapi = AsyncMock(return_value={
            "uuid": "alert-123",
            "short_id": "AL-123",
            "events_count": 200,
            "rule": {"uuid": "rule-456", "name": "Test Rule"},
        })
        
        trigger._count_events_in_time_window = AsyncMock(return_value=50)
        
        notification = {
            "alert": {"uuid": "alert-123"},
        }
        
        await trigger._process_alert_update(notification)
        
        # Should trigger send_event
        trigger.send_event.assert_called_once()
        
        # Verify payload structure
        call_args = trigger.send_event.call_args
        event_name = call_args[1]["event_name"]
        payload = call_args[1]["event"]
        
        assert "AL-123" in event_name
        assert "alert" in payload
        assert "trigger_context" in payload
        assert payload["trigger_context"]["trigger_type"] == "alert_events_threshold"


class TestEventCounting:
    """Test event counting in time windows."""

    @pytest.mark.asyncio
    async def test_count_events_success(self, trigger):
        """Test successful event counting."""
        # Mock HTTP session
        mock_response = AsyncMock()
        mock_response.raise_for_status = Mock()
        mock_response.json = AsyncMock(return_value={"total": 42})
        
        trigger.session = AsyncMock()
        trigger.session.post = AsyncMock(return_value=mock_response)
        trigger.session.__aenter__ = AsyncMock(return_value=trigger.session)
        trigger.session.__aexit__ = AsyncMock()
        
        count = await trigger._count_events_in_time_window("alert-123", 1)
        
        assert count == 42

    @pytest.mark.asyncio
    async def test_count_events_error_returns_zero(self, trigger):
        """Test that event counting errors return 0."""
        # Mock HTTP session with error
        trigger.session = AsyncMock()
        trigger.session.post = AsyncMock(side_effect=Exception("API error"))
        
        count = await trigger._count_events_in_time_window("alert-123", 1)
        
        assert count == 0
        trigger.log.assert_called()


class TestStateCleanup:
    """Test state cleanup functionality."""

    @pytest.mark.asyncio
    async def test_cleanup_skipped_if_recent(self, trigger, temp_data_dir):
        """Test that cleanup is skipped if run recently."""

        
        trigger.state_manager = AlertStateManager(
            temp_data_dir / "state.json",
            logger=trigger.log
        )
        
        # Set recent cleanup time
        trigger._last_cleanup = datetime.now(timezone.utc)
        
        await trigger._cleanup_old_states()
        
        # Should not have logged cleanup
        cleanup_logs = [
            call for call in trigger.log.call_args_list
            if "State cleanup" in str(call)
        ]
        assert len(cleanup_logs) == 0

    @pytest.mark.asyncio
    async def test_cleanup_removes_old_entries(self, trigger, temp_data_dir):
        """Test that old entries are removed during cleanup."""

        
        trigger.state_manager = AlertStateManager(
            temp_data_dir / "state.json",
            logger=trigger.log
        )
        
        # Add old state entry
        old_date = datetime.now(timezone.utc) - timedelta(days=60)
        trigger.state_manager._state["alerts"]["old-alert"] = {
            "alert_uuid": "old-alert",
            "last_triggered_at": old_date.isoformat(),
        }
        trigger.state_manager._save_state()
        
        # Force cleanup
        trigger._last_cleanup = None
        trigger.configuration.state_cleanup_days = 30
        
        await trigger._cleanup_old_states()
        
        # Old entry should be removed
        assert "old-alert" not in trigger.state_manager._state["alerts"]


class TestWebSocketIntegration:
    """Test WebSocket integration."""

    @pytest.mark.asyncio
    async def test_websocket_connection(self, trigger):
        """Test WebSocket connection establishment."""
        # Mock aiohttp WebSocket
        mock_ws = AsyncMock()
        
        trigger.session = AsyncMock()
        trigger.session.ws_connect = AsyncMock(return_value=mock_ws)
        
        ws = await trigger._connect_websocket()
        
        assert ws == mock_ws
        trigger.log.assert_called()
        assert any("Connected" in str(call) for call in trigger.log.call_args_list)

    @pytest.mark.asyncio
    async def test_websocket_message_processing(self, trigger, temp_data_dir):
        """Test processing of WebSocket messages."""

        
        trigger.state_manager = AlertStateManager(
            temp_data_dir / "state.json",
            logger=trigger.log
        )
        
        # Mock successful alert processing
        trigger._retrieve_alert_from_alertapi = AsyncMock(return_value={
            "uuid": "alert-123",
            "short_id": "AL-123",
            "events_count": 200,
            "rule": {"uuid": "rule-456", "name": "Test Rule"},
        })
        
        # Create mock WebSocket message
        mock_msg = Mock()
        mock_msg.type = WSMsgType.TEXT
        mock_msg.json = Mock(return_value={
            "event": "alert.updated",
            "alert": {"uuid": "alert-123"},
        })
        
        # Process message directly
        data = mock_msg.json()
        if data.get("event") == "alert.updated":
            await trigger._process_alert_update(data)
        
        # Verify send_event was called
        trigger.send_event.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])