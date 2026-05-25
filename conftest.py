"""pytest configuration for the iam-service test suite."""

from __future__ import annotations

# exclude test file from the superadmin-ip-whitelist feature branch that was
# carried over as an untracked working-tree file; it references permissions
# that don't exist on this branch and causes a collection-time ImportError
collect_ignore = [
    "apps/users/tests/unit/test_superadmin_ip_whitelist.py",
]
