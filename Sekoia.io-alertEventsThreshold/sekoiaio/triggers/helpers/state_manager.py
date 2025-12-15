"""
Alert State Manager for persistent threshold tracking.

Manages persistent state for alert event thresholds with atomic file operations
and proper locking to prevent race conditions.
"""

import fcntl
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Callable


class AlertStateManager:
    """
    Manages persistent state for alert event thresholds.

    State structure:
    {
        "alerts": {
            "alert-uuid": {
                "alert_uuid": str,
                "alert_short_id": str,
                "rule_uuid": str,
                "rule_name": str,
                "last_triggered_at": str (ISO 8601),
                "last_triggered_event_count": int,
                "total_triggers": int,
                "created_at": str (ISO 8601),
                "updated_at": str (ISO 8601),
                "version": int,
            }
        },
        "metadata": {
            "version": str,
            "last_cleanup": str (ISO 8601),
        }
    }
    """

    VERSION = "1.0"

    def __init__(self, state_file_path: Path, logger: Optional[Callable] = None):
        """
        Initialize state manager.

        Args:
            state_file_path: Path to the state JSON file
            logger: Optional logger callable (trigger.log or logger.error)
        """
        self.state_file_path = Path(state_file_path)
        self.logger = logger
        self._state: dict[str, Any] = self._load_state()

    def _log_error(self, message: str, exc_info=None):
        """Helper to log errors using the injected logger."""
        if self.logger:
            # Support both function-style loggers (trigger.log) and logger objects
            if callable(self.logger):
                try:
                    # Try trigger.log signature: log(message, level)
                    self.logger(message=message, level="error")
                except TypeError:
                    # Fallback to standard logger.error()
                    if hasattr(self.logger, 'error'):
                        self.logger.error(message, exc_info=exc_info)
            elif hasattr(self.logger, 'error'):
                self.logger.error(message, exc_info=exc_info)

    def _locked_load_state(self, file_obj) -> dict[str, Any]:
        """
        Load JSON from an already locked file object.
        
        Args:
            file_obj: Open file object with shared lock
            
        Returns:
            State dictionary with validated structure
        """
        file_obj.seek(0)
        
        try:
            state = json.load(file_obj)
        except json.JSONDecodeError as exc:
            self._log_error("State file corrupted; starting fresh", exc_info=exc)
            return self._create_empty_state()

        # Ensure structure + version
        if state.get("metadata", {}).get("version") != self.VERSION:
            state = self._migrate_state(state)

        state.setdefault("alerts", {})
        state.setdefault("metadata", self._create_metadata())
        
        return state

    def _locked_save_state(self, file_obj):
        """
        Write JSON to an already locked file object.
        
        Args:
            file_obj: Open file object with exclusive lock
        """
        file_obj.seek(0)
        file_obj.truncate()
        json.dump(self._state, file_obj, indent=2)
        file_obj.flush()

    def _create_empty_state(self) -> dict[str, Any]:
        """Create a new empty state structure."""
        return {
            "alerts": {},
            "metadata": self._create_metadata(),
        }

    def _create_metadata(self) -> dict[str, str]:
        """Create metadata dictionary with current timestamp."""
        return {
            "version": self.VERSION,
            "last_cleanup": datetime.now(timezone.utc).isoformat(),
        }

    def _load_state(self) -> dict[str, Any]:
        """
        Load state from file with proper locking and error handling.
        
        Returns:
            State dictionary
        """
        if not self.state_file_path.exists():
            return self._create_empty_state()

        try:
            with open(self.state_file_path, "r") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
                try:
                    state = json.load(f)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
            # Migration + defaults
            if state.get("metadata", {}).get("version") != self.VERSION:
                state = self._migrate_state(state)
                
            state.setdefault("alerts", {})
            state.setdefault("metadata", self._create_metadata())
            
            return state
            
        except Exception as exc:
            self._log_error(
                "State file corrupted or unreadable; starting fresh",
                exc_info=exc
            )
            return self._create_empty_state()

    def _save_state(self):
        """
        Save state to file with atomic write and locking.
        
        Uses temporary file + atomic rename to prevent corruption.
        """
        # Create parent directory if needed
        self.state_file_path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write using temporary file + rename
        temp_fd, temp_path = tempfile.mkstemp(
            dir=str(self.state_file_path.parent),
            prefix=".tmp_state_",
            suffix=".json",
        )

        try:
            # Open by fd to ensure correct handle is locked
            with open(temp_fd, "w") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # Exclusive lock for writing
                try:
                    json.dump(self._state, f, indent=2)
                    f.flush()
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            # Atomic rename
            Path(temp_path).rename(self.state_file_path)
            
        except Exception as e:
            # Clean up temp file on error
            try:
                Path(temp_path).unlink(missing_ok=True)
            except Exception:
                pass
            self._log_error(f"Failed to save state file: {e}")
            raise

    def _migrate_state(self, old_state: dict[str, Any]) -> dict[str, Any]:
        """
        Migrate state from older versions.
        
        Args:
            old_state: State dictionary from older version
            
        Returns:
            Migrated state dictionary
        """
        # Future: implement version migrations here
        # For now, ensure basic structure exists
        old_state.setdefault("alerts", {})
        old_state.setdefault("metadata", self._create_metadata())
        old_state["metadata"]["version"] = self.VERSION
        
        return old_state

    def get_alert_state(self, alert_uuid: str) -> Optional[dict[str, Any]]:
        """
        Get state for a specific alert.

        Args:
            alert_uuid: UUID of the alert

        Returns:
            Alert state dictionary or None if not found
        """
        return self._state["alerts"].get(alert_uuid)

    def update_alert_state(
        self,
        alert_uuid: str,
        alert_short_id: str,
        rule_uuid: str,
        rule_name: str,
        event_count: int,
        previous_version: Optional[int] = None,
    ):
        """
        Update the state for a specific alert with full file locking.
        
        Performs atomic read-modify-write with file-level locking to prevent
        race conditions in multi-process environments.

        Args:
            alert_uuid: UUID of the alert
            alert_short_id: Short ID of the alert
            rule_uuid: UUID of the rule
            rule_name: Name of the rule
            event_count: Current event count
            previous_version: Expected version for optimistic locking (reserved)
        """
        now = datetime.now(timezone.utc).isoformat()

        # Ensure state file exists before opening
        if not self.state_file_path.exists():
            self.state_file_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_file_path.write_text(
                json.dumps(self._create_empty_state())
            )

        # FULL FILE LOCK OVER THE ENTIRE READ → MODIFY → WRITE
        with open(self.state_file_path, "r+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # Exclusive lock
            try:
                # Load fresh state from file
                self._state = self._locked_load_state(f)

                existing = self._state["alerts"].get(alert_uuid)

                if existing:
                    # Update existing alert state
                    current_version = existing.get("version", 0)
                    existing.update({
                        "alert_short_id": alert_short_id,
                        "rule_uuid": rule_uuid,
                        "rule_name": rule_name,
                        "last_triggered_at": now,
                        "last_triggered_event_count": event_count,
                        "total_triggers": existing.get("total_triggers", 0) + 1,
                        "updated_at": now,
                        "version": current_version + 1,
                    })
                else:
                    # Create new alert state
                    self._state["alerts"][alert_uuid] = {
                        "alert_uuid": alert_uuid,
                        "alert_short_id": alert_short_id,
                        "rule_uuid": rule_uuid,
                        "rule_name": rule_name,
                        "last_triggered_at": now,
                        "last_triggered_event_count": event_count,
                        "total_triggers": 1,
                        "created_at": now,
                        "updated_at": now,
                        "version": 1,
                    }

                # Save back to file
                self._locked_save_state(f)
                
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    def cleanup_old_states(self, cutoff_date: datetime) -> int:
        """
        Remove state entries for alerts not triggered since cutoff date.
        
        Uses ISO 8601 string comparison (lexicographically sortable).

        Args:
            cutoff_date: Remove entries older than this date

        Returns:
            Number of entries removed
        """
        cutoff_iso = cutoff_date.isoformat()
        to_remove = []

        # Find alerts to remove (ISO format is lexicographically sortable)
        for alert_uuid, state in list(self._state["alerts"].items()):
            last_triggered = state.get("last_triggered_at", "")
            
            # If last_triggered is earlier than cutoff, remove it
            if last_triggered and last_triggered < cutoff_iso:
                to_remove.append(alert_uuid)

        # Remove identified alerts
        for alert_uuid in to_remove:
            del self._state["alerts"][alert_uuid]

        # Update metadata and save if any removals occurred
        if to_remove:
            self._state["metadata"]["last_cleanup"] = datetime.now(timezone.utc).isoformat()
            self._save_state()

        return len(to_remove)

    def get_stats(self) -> dict[str, Any]:
        """
        Get statistics about the current state.

        Returns:
            Dictionary with statistics (total_alerts, version, last_cleanup)
        """
        return {
            "total_alerts": len(self._state["alerts"]),
            "version": self._state["metadata"]["version"],
            "last_cleanup": self._state["metadata"]["last_cleanup"],
        }