"""
PrivWatch 3.0 / UATU Linux Edition - Platform Validator Compatibility Wrapper
Re-exports LinuxPlatform, UnsupportedPlatformError, and CapabilityReport from core.platform.
"""

from core.platform import (
    UnsupportedPlatformError,
    CapabilityReport,
    LinuxSystemReport,
    LinuxPlatform,
    LinuxPlatformValidator
)

__all__ = [
    "UnsupportedPlatformError",
    "CapabilityReport",
    "LinuxSystemReport",
    "LinuxPlatform",
    "LinuxPlatformValidator"
]
