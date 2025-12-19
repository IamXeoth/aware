"""Git hooks installation and management."""

from .install import (
    HookInstaller,
    check_hooks_status,
    install_hooks,
    uninstall_hooks,
)

__all__ = [
    "HookInstaller",
    "check_hooks_status",
    "install_hooks",
    "uninstall_hooks",
]