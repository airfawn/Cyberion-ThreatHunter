from .collector import Collector, detect_runtime_platform, gather_initial_data
from .log_queue import LogQueue, LogSender, LogEntry


def __getattr__(name):
	# Lazy import avoids RuntimeWarning when running "python -m Agent.connector".
	if name == "connector":
		from .connector import connector as _connector

		return _connector
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
	"connector",
	"Collector",
	"detect_runtime_platform",
	"gather_initial_data",
	"LogQueue",
	"LogSender",
	"LogEntry",
]