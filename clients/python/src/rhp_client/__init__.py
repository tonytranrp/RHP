"""rhp_client: a pure-Python client for RHP (Remote Hot Patch) hosts.

Speaks RHP's native protocol (revision 6) over TCP, or TLS 1.3 with pyOpenSSL installed: the
pre-shared-key handshake, signed scripts, every host operation (releases, tunables, the profiler
and the debugger included), script output and events. See
clients/python/README.md.
"""

from ._errors import RhpError
from ._frame import PROTOCOL_REVISION
from .client import Client, Event, ModuleStatus, ProfileReport, RevertSummary, Tunable, connect
from .identity import Identity

__all__ = ["Client", "Event", "Identity", "ModuleStatus", "PROTOCOL_REVISION", "ProfileReport", "RevertSummary", "RhpError", "Tunable", "connect"]
