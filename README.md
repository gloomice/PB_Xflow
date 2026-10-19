# PB X-Flow

Enterprise-grade high-speed file copy engine for Windows (PB-scale / millions of small files).

Repository: https://github.com/gloomice/PB_Xflow

## Components

| Path | Description |
|------|-------------|
| `pb_xflow.c` | Copy engine (V124) |
| `pb_xflow_gui.py` / `pb_xflow_gui_qt.py` | GUI front-ends |
| `build_pb_xflow.bat` | MSVC build script |
| `build_pb_xflow_gui.bat` | Nuitka GUI build |
| `release_xflow/` | Prebuilt `pb_xflow.exe` / `pb_xflow_gui.exe` |

## Build (engine)

```bat
build_pb_xflow.bat nopause
```

Requires Visual Studio 2019+ x64 toolchain (`vcvarsall.bat`).

## Quick run

```bat
pb_xflow.exe -s <src> -d <dst> -J -F -t 24
```

Admin is required for `-mft_scan` / `-mft_raw`.

## License / Copyright

Copyright (C) 2025-2026 www.linkleading.com
