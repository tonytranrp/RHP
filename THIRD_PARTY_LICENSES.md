# Third-party code in RHP

RHP fetches every dependency at a pinned commit or hash (`cmake/Dependencies.cmake`) and compiles
it into its own static libraries; nothing is downloaded at run time. This table lists what ends up
in a build, and when. An installed RHP carries each license text in `share/doc/rhp/licenses/`.

| Component | Pin | License (as used by RHP) | In which build | Where |
|---|---|---|---|---|
| [Lua](https://www.lua.org) 5.5.1 | `v5.5.1` = `7579fc9d7ed90240487251dfb69168f8e64e9294` | MIT | `RHP_ENABLE=ON` | compiled as C++ into `rhp_lua` (linked by `Rhp::script`) |
| [Monocypher](https://monocypher.org) 4.0.3 | `4.0.3` = `ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f` | CC0-1.0 (dual: BSD-2-Clause OR CC0-1.0) | `RHP_ENABLE=ON` | compiled as C++ into `rhp_monocypher` (linked by `Rhp::security`) |
| [Asio](https://think-async.com/Asio/) 1.38.2 | `asio-1-38-2` = `8806a6803cde7054c3049d3666d3ec36786568c5` | BSL-1.0 | `RHP_ENABLE=ON` | header-only, inside `rhp_net`; headers are not installed |
| [Mbed TLS](https://www.trustedfirmware.org/projects/mbed-tls/) 4.2.0 with TF-PSA-Crypto | release tarball, SHA-256 `2bed9d71...6ffea` | Apache-2.0 (dual: Apache-2.0 OR GPL-2.0-or-later) | `RHP_WITH_TLS=ON`, `RHP_TLS_MBEDTLS=ON` | `mbedtls`, `mbedx509`, `tfpsacrypto` archives (linked by `Rhp::tls`) |
| [OpenSSL](https://www.openssl.org) >= 3.0 | the system's | Apache-2.0 | `RHP_TLS_OPENSSL=AUTO/ON` and found | linked from the system, not shipped |
| [CLI11](https://github.com/CLIUtils/CLI11) 2.7.2 | `v2.7.2` = `cbd58a3696887b34c70949aef21a71735a0c2ad5` | BSD-3-Clause | `RHP_BUILD_TOOLS=ON` | `rhp-cli` only |
| [replxx](https://github.com/AmokHuginnsson/replxx) 0.0.4 | `release-0.0.4` = `2b248467112cbbc16f63fde38230fd7c7ffc55f1` | BSD-3-Clause (includes ConvertUTF, Unicode, Inc., and wcwidth, Markus Kuhn) | `RHP_BUILD_TOOLS=ON` | `rhp-cli` only |
| [Catch2](https://github.com/catchorg/Catch2) 3.16.1 | `v3.16.1` = `08092139210881f01a34e60c5f2fd6afa0ea4024` | BSL-1.0 | `RHP_BUILD_TESTS=ON` | test executables only |
| [CPM.cmake](https://github.com/cpm-cmake/CPM.cmake) 0.42.3 | SHA-256 `a609e875...25c844` | MIT | configure time | build scripts only |

Copyright notices:

- Lua: Copyright (C) 1994-2026 Lua.org, PUC-Rio.
- Monocypher: Copyright (c) 2017-2023 Loup Vaillant; (c) 2017-2019 Michael Savage; (c) 2017-2023 Fabio Scotoni.
- Asio: Copyright (c) 2003-2026 Christopher M. Kohlhoff.
- Mbed TLS / TF-PSA-Crypto: Copyright The Mbed TLS Contributors.
- CLI11: Copyright (c) 2017-2026 University of Cincinnati, developed by Henry Schreiner under NSF AWARD 1414736.
- replxx: Copyright (c) 2017-2018 Marcin Konarski; (c) 2010 Salvatore Sanfilippo; (c) 2010 Pieter Noordhuis; ConvertUTF Copyright 2001-2004 Unicode, Inc.

RHP's own MessagePack codec, CRC32C, frames and protocol are original code under RHP's Apache-2.0
license (`LICENSE`, `NOTICE`).
