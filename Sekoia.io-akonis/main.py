# flake8: noqa: E402
from sekoiaio.utils import should_patch

if should_patch():
    from gevent import monkey

    monkey.patch_all()

from sekoia_automation.module import Module

from sekoiaio.triggers.alert_events_threshold import AlertEventsThresholdTrigger

if __name__ == "__main__":
    module = Module()
    module.register(AlertEventsThresholdTrigger, "alert_events_threshold_trigger")

    module.run()
