# Local IPC

`Rhp::config<>::transport<Rhp::net::local_ipc>`. `endpoint.host` names the endpoint, `endpoint.port` must be 0. Listening and reverse dialing both work; PSK authentication is still required.

| Platform | Endpoint | Access control |
|---|---|---|
| Windows | `name` → `\\.\pipe\rhp.<name>` (letters, digits, `.`, `_`, `-`) | first instance only (`FILE_FLAG_FIRST_PIPE_INSTANCE`), DACL for the owner and SYSTEM, remote clients refused; dialers open with `SECURITY_IDENTIFICATION`, so the pipe's owner can't impersonate them |
| POSIX | an absolute socket path | created mode 0600; cleanup removes only the listener's own device/inode, never a pre-existing file. Put it in an application-private directory. |
| Linux, Android | `@name`: an abstract socket | no file at all; both ends check the peer's UID (`SO_PEERCRED`), which pathname sockets also get on Linux |

Busy Windows pipes are retried for up to five seconds without blocking the reactor. The transport reports `loopback()`, so the TLS address rules treat it as local; `require_tls` still adds TLS.
