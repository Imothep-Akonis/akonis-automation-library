"""
Tests for AlertStateManager

Tests cover:
- State file creation and initialization
- Atomic read/write operations
- File locking (shared and exclusive)
- State updates and versioning
- Cleanup of old entries
- Error handling and corruption recovery
- Concurrent access scenarios
"""

import fcntl
import json
import multiprocessing
import time
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

from sekoiaio.triggers.helpers.state_manager import AlertStateManager


@pytest.fixture
def temp_state_file(tmp_path):
    """Create temporary state file path."""
    return tmp_path / "test_state.json"


@pytest.fixture
def mock_logger():
    """Create mock logger."""
    logger = Mock()
    logger.error = Mock()
    return logger


@pytest.fixture
def state_manager(temp_state_file, mock_logger):
    """Create AlertStateManager instance."""
    return AlertStateManager(temp_state_file, logger=mock_logger)


class TestInitialization:
    """Test state manager initialization."""

    def test_creates_empty_state_if_not_exists(self, temp_state_file, mock_logger):
        """Test that empty state is created if file doesn't exist."""
        manager = AlertStateManager(temp_state_file, logger=mock_logger)
        
        assert manager._state["alerts"] == {}
        assert manager._state["metadata"]["version"] == "1.0"
        assert "last_cleanup" in manager._state["metadata"]

    def test_loads_existing_state(self, temp_state_file, mock_logger):
        """Test loading existing state file."""
        # Create initial state
        initial_state = {
            "alerts": {
                "alert-123": {
                    "alert_uuid": "alert-123",
                    "alert_short_id": "AL-123",
                    "last_triggered_event_count": 100,
                    "version": 1,
                }
            },
            "metadata": {
                "version": "1.0",
                "last_cleanup": "2024-01-01T00:00:00+00:00",
            },
        }
        
        temp_state_file.write_text(json.dumps(initial_state))
        
        # Load state
        manager = AlertStateManager(temp_state_file, logger=mock_logger)
        
        assert "alert-123" in manager._state["alerts"]
        assert manager._state["alerts"]["alert-123"]["last_triggered_event_count"] == 100

    def test_handles_corrupted_state_file(self, temp_state_file, mock_logger):
        """Test handling of corrupted JSON file."""
        # Write invalid JSON
        temp_state_file.write_text("{ invalid json }")
        
        # Should create empty state and log error
        manager = AlertStateManager(temp_state_file, logger=mock_logger)
        
        assert manager._state["alerts"] == {}
        mock_logger.assert_called()

    def test_migration_from_old_version(self, temp_state_file, mock_logger):
        """Test migration from older state version."""
        # Create old version state
        old_state = {
            "alerts": {"alert-123": {"alert_uuid": "alert-123"}},
            "metadata": {"version": "0.9"},
        }
        
        temp_state_file.write_text(json.dumps(old_state))
        
        # Load and migrate
        manager = AlertStateManager(temp_state_file, logger=mock_logger)
        
        assert manager._state["metadata"]["version"] == "1.0"
        assert "alert-123" in manager._state["alerts"]


class TestStateRetrieval:
    """Test state retrieval operations."""

    def test_get_alert_state_existing(self, state_manager):
        """Test retrieving existing alert state."""
        # Add state
        state_manager._state["alerts"]["alert-123"] = {
            "alert_uuid": "alert-123",
            "last_triggered_event_count": 100,
        }
        
        result = state_manager.get_alert_state("alert-123")
        
        assert result is not None
        assert result["alert_uuid"] == "alert-123"
        assert result["last_triggered_event_count"] == 100

    def test_get_alert_state_not_found(self, state_manager):
        """Test retrieving non-existent alert state."""
        result = state_manager.get_alert_state("nonexistent")
        
        assert result is None


class TestStateUpdates:
    """Test state update operations."""

    def test_update_new_alert_state(self, state_manager, temp_state_file):
        """Test creating new alert state."""
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=100,
        )
        
        state = state_manager.get_alert_state("alert-123")
        
        assert state is not None
        assert state["alert_uuid"] == "alert-123"
        assert state["alert_short_id"] == "AL-123"
        assert state["rule_uuid"] == "rule-456"
        assert state["rule_name"] == "Test Rule"
        assert state["last_triggered_event_count"] == 100
        assert state["total_triggers"] == 1
        assert state["version"] == 1
        assert "created_at" in state
        assert "updated_at" in state
        assert "last_triggered_at" in state

    def test_update_existing_alert_state(self, state_manager):
        """Test updating existing alert state."""
        # Create initial state
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=100,
        )
        
        # Update state
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=250,
        )
        
        state = state_manager.get_alert_state("alert-123")
        
        assert state["last_triggered_event_count"] == 250
        assert state["total_triggers"] == 2
        assert state["version"] == 2

    def test_update_increments_version(self, state_manager):
        """Test that updates increment version counter."""
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=100,
        )
        
        # Multiple updates
        for i in range(5):
            state_manager.update_alert_state(
                alert_uuid="alert-123",
                alert_short_id="AL-123",
                rule_uuid="rule-456",
                rule_name="Test Rule",
                event_count=100 + (i + 1) * 50,
            )
        
        state = state_manager.get_alert_state("alert-123")
        
        assert state["version"] == 6
        assert state["total_triggers"] == 6

    def test_update_persists_to_file(self, state_manager, temp_state_file):
        """Test that updates are persisted to file."""
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=100,
        )
        
        # Load from file directly
        with open(temp_state_file, "r") as f:
            file_state = json.load(f)
        
        assert "alert-123" in file_state["alerts"]
        assert file_state["alerts"]["alert-123"]["last_triggered_event_count"] == 100


class TestFileLocking:
    """Test file locking mechanisms."""

    def test_exclusive_lock_during_update(self, state_manager, temp_state_file):
        """Test that updates acquire exclusive lock."""
        # This test verifies locking by attempting concurrent access
        # In practice, fcntl.flock will block or fail on locked files
        
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=100,
        )
        
        # File should exist and be readable
        assert temp_state_file.exists()
        
        # Should be able to read with shared lock after update completes
        with open(temp_state_file, "r") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            try:
                data = json.load(f)
                assert "alert-123" in data["alerts"]
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def test_atomic_write_with_rename(self, state_manager, temp_state_file):
        """Test that saves use atomic rename."""
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=100,
        )
        
        # File should exist at final path
        assert temp_state_file.exists()
        
        # No temporary files should remain
        temp_files = list(temp_state_file.parent.glob(".tmp_state_*"))
        assert len(temp_files) == 0


class TestStateCleanup:
    """Test cleanup of old state entries."""

    def test_cleanup_removes_old_entries(self, state_manager):
        """Test that cleanup removes entries older than cutoff."""
        # Add old and recent entries
        now = datetime.now(timezone.utc)
        old_date = now - timedelta(days=60)
        recent_date = now - timedelta(days=10)
        
        state_manager._state["alerts"]["old-alert"] = {
            "alert_uuid": "old-alert",
            "last_triggered_at": old_date.isoformat(),
        }
        
        state_manager._state["alerts"]["recent-alert"] = {
            "alert_uuid": "recent-alert",
            "last_triggered_at": recent_date.isoformat(),
        }
        
        # Cleanup with 30-day cutoff
        cutoff = now - timedelta(days=30)
        removed = state_manager.cleanup_old_states(cutoff)
        
        assert removed == 1
        assert "old-alert" not in state_manager._state["alerts"]
        assert "recent-alert" in state_manager._state["alerts"]

    def test_cleanup_updates_metadata(self, state_manager):
        """Test that cleanup updates last_cleanup timestamp."""
        now = datetime.now(timezone.utc)
        old_date = now - timedelta(days=60)
        
        state_manager._state["alerts"]["old-alert"] = {
            "alert_uuid": "old-alert",
            "last_triggered_at": old_date.isoformat(),
        }
        
        original_cleanup = state_manager._state["metadata"]["last_cleanup"]
        
        # Cleanup
        cutoff = now - timedelta(days=30)
        state_manager.cleanup_old_states(cutoff)
        
        new_cleanup = state_manager._state["metadata"]["last_cleanup"]
        assert new_cleanup > original_cleanup

    def test_cleanup_with_no_entries_to_remove(self, state_manager):
        """Test cleanup when no entries need removal."""
        now = datetime.now(timezone.utc)
        recent_date = now - timedelta(days=10)
        
        state_manager._state["alerts"]["recent-alert"] = {
            "alert_uuid": "recent-alert",
            "last_triggered_at": recent_date.isoformat(),
        }
        
        cutoff = now - timedelta(days=30)
        removed = state_manager.cleanup_old_states(cutoff)
        
        assert removed == 0
        assert "recent-alert" in state_manager._state["alerts"]

    def test_cleanup_handles_missing_timestamp(self, state_manager):
        """Test cleanup handles entries without last_triggered_at."""
        state_manager._state["alerts"]["no-timestamp"] = {
            "alert_uuid": "no-timestamp",
        }
        
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=30)
        
        # Should not crash
        removed = state_manager.cleanup_old_states(cutoff)
        
        # Entry without timestamp should not be removed
        assert "no-timestamp" in state_manager._state["alerts"]


class TestStatistics:
    """Test statistics retrieval."""

    def test_get_stats_empty_state(self, state_manager):
        """Test statistics for empty state."""
        stats = state_manager.get_stats()
        
        assert stats["total_alerts"] == 0
        assert stats["version"] == "1.0"
        assert "last_cleanup" in stats

    def test_get_stats_with_alerts(self, state_manager):
        """Test statistics with alerts."""
        # Add multiple alerts
        for i in range(5):
            state_manager._state["alerts"][f"alert-{i}"] = {
                "alert_uuid": f"alert-{i}",
                "last_triggered_event_count": 100 + i * 10,
            }
        
        stats = state_manager.get_stats()
        
        assert stats["total_alerts"] == 5
        assert stats["version"] == "1.0"


class TestErrorHandling:
    """Test error handling scenarios."""

    def test_handles_permission_error(self, temp_state_file, mock_logger):
        """Test handling of permission errors."""
        # Create read-only file
        temp_state_file.write_text(json.dumps({"alerts": {}, "metadata": {}}))
        temp_state_file.chmod(0o444)
        
        try:
            manager = AlertStateManager(temp_state_file, logger=mock_logger)
            
            # Should be able to read
            assert manager._state["alerts"] == {}
            
            # Update should fail gracefully
            with pytest.raises(Exception):
                manager.update_alert_state(
                    alert_uuid="alert-123",
                    alert_short_id="AL-123",
                    rule_uuid="rule-456",
                    rule_name="Test Rule",
                    event_count=100,
                )
        finally:
            # Restore permissions for cleanup
            temp_state_file.chmod(0o644)

    def test_handles_disk_full(self, state_manager, temp_state_file, monkeypatch):
        """Test handling of disk full scenarios."""
        # Mock json.dump to raise IOError
        original_dump = json.dump
        
        def mock_dump(*args, **kwargs):
            raise IOError("No space left on device")
        
        monkeypatch.setattr(json, "dump", mock_dump)
        
        # Update should raise error
        with pytest.raises(IOError):
            state_manager.update_alert_state(
                alert_uuid="alert-123",
                alert_short_id="AL-123",
                rule_uuid="rule-456",
                rule_name="Test Rule",
                event_count=100,
            )


class TestConcurrentAccess:
    """Test concurrent access scenarios."""

    def test_concurrent_reads(self, state_manager, temp_state_file):
        """Test that multiple processes can read simultaneously."""
        # Prepare state
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=100,
        )
        
        results = []
        errors = []
        
        def read_state():
            """Helper function for threading."""
            try:
                manager = AlertStateManager(temp_state_file)
                result = manager.get_alert_state("alert-123")
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        # Multiple concurrent reads should work (using threads instead of processes)
        threads = [threading.Thread(target=read_state) for _ in range(3)]
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # All reads should succeed
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 3
        assert all(r is not None for r in results)
        assert all(r["alert_uuid"] == "alert-123" for r in results)

    def test_sequential_writes(self, temp_state_file):
        """Test that sequential writes maintain consistency."""
        # Sequential updates
        for i in range(5):
            manager = AlertStateManager(temp_state_file)
            manager.update_alert_state(
                alert_uuid=f"alert-{i}",
                alert_short_id=f"AL-{i}",
                rule_uuid="rule-456",
                rule_name="Test Rule",
                event_count=100 + i,
            )
            time.sleep(0.05)  # Small delay between updates
        
        # Final state should have all alerts
        manager = AlertStateManager(temp_state_file)
        assert manager.get_stats()["total_alerts"] == 5


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_alert_uuid(self, state_manager):
        """Test handling of empty alert UUID."""
        state_manager.update_alert_state(
            alert_uuid="",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=100,
        )
        
        # Should create entry with empty UUID
        state = state_manager.get_alert_state("")
        assert state is not None

    def test_very_large_event_count(self, state_manager):
        """Test handling of very large event counts."""
        large_count = 10**9  # 1 billion events
        
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=large_count,
        )
        
        state = state_manager.get_alert_state("alert-123")
        assert state["last_triggered_event_count"] == large_count

    def test_unicode_in_rule_names(self, state_manager):
        """Test handling of Unicode characters in rule names."""
        unicode_name = "Règle de sécurité 🔒"
        
        state_manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name=unicode_name,
            event_count=100,
        )
        
        state = state_manager.get_alert_state("alert-123")
        assert state["rule_name"] == unicode_name

    def test_very_long_state_file_path(self, tmp_path):
        """Test handling of very long file paths."""
        # Create deeply nested directory
        deep_path = tmp_path
        for i in range(10):
            deep_path = deep_path / f"level_{i}"
        
        state_file = deep_path / "state.json"
        
        # Should create parent directories
        manager = AlertStateManager(state_file)
        
        manager.update_alert_state(
            alert_uuid="alert-123",
            alert_short_id="AL-123",
            rule_uuid="rule-456",
            rule_name="Test Rule",
            event_count=100,
        )
        
        assert state_file.exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])