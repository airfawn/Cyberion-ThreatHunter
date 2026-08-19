from __future__ import annotations

import logging
from pathlib import Path


SENSITIVE_KEYS = {"token", "enrollment_token", "password", "api_key", "private_key", "secret"}


def redact(text: str) -> str:
    lowered = text.lower()
    for key in SENSITIVE_KEYS:
        marker = f"{key}="
        if marker in lowered:
            start = lowered.index(marker)
            end = text.find(" ", start)
            if end == -1:
                end = len(text)
            text = text[: start + len(marker)] + "[REDACTED]" + text[end:]
            lowered = text.lower()
    return text


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        return redact(msg)


def get_logger(log_file: Path, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("cyberion_installer")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers = []
    log_file.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(message)s"))

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter("%(message)s"))

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger
