"""Hook to verify and load offline threat intelligence bundles into runtime detectors."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .detectors.denylist import DenylistDetector

logger = logging.getLogger("guardian_net.bundle_hook")


def load_threat_bundle(
    bundle_path: str | Path,
    signing_key: bytes,
    detector: DenylistDetector,
    minimum_version: int = 0,
) -> bool:
    """Read a JSON bundle file, verify integrity & signature, and populate detector denylist."""
    p = Path(bundle_path)
    if not p.exists():
        logger.warning(f"Threat bundle not found: {p}")
        return False

    try:
        content = json.loads(p.read_text(encoding="utf-8"))
        detector.load_bundle(content, signing_key, minimum_version=minimum_version)
        logger.info(f"Loaded verified threat intelligence bundle v{detector.bundle_version} from {p}")
        return True
    except Exception as err:
        logger.error(f"Failed to load verified threat bundle from {p}: {err}")
        raise
