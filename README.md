# airplayclib

A Windows C++20 static library for receiving AirPlay/RAOP audio. It advertises
a speaker through DNS-SD, handles RTSP/RAOP sessions, decrypts FairPlay v3 and
RAOP AES-CBC audio, decodes ALAC, and emits interleaved S16 PCM, metadata,
artwork, volume, progress, and lifecycle callbacks.

This is an archival, unmaintained release. It is unofficial and is not
affiliated with or endorsed by Apple Inc.

## Compatibility limits

- System AirPlay from tested iPhone and macOS senders using FairPlay v3 works.
- Direct output from Apple Music desktop clients that require FairPlay v2 is
  unsupported.
- ALAC is supported. AAC-ELD is not implemented.
- Sender control uses DACP and is sender-dependent; absolute seeking is not
  available from iOS senders.

These limits make the library useful for callback-based Windows receiver
projects, but not a general complete AirPlay 2 implementation.

## Build

Requirements: Windows 10/11 and Visual Studio 2022 with the v143 C++ toolset
and Windows SDK.

```powershell
msbuild airplayclib.sln /m /p:Configuration=Release /p:Platform=x64
```

This produces `bin/airplayc.lib` and `bin/harness.exe`. Run
`bin/harness.exe --self-test` for the offline crypto check or
`bin/harness.exe --help` for the standalone receiver options. The stable host
surface is `include/airplayc/airplayc.h`.

## License

GPL-3.0-only because the FairPlay implementation is based in part on PlayFair.
See `LICENSE`, `THIRD_PARTY_NOTICES.md`, and `deps/alac/LICENSE`.

Copyright (c) 2026 matkhl.
