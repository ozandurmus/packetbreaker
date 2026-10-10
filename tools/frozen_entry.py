"""Native one-file entry point; the pip CLI remains the application entry point."""

import multiprocessing
import os
import sys


if __name__ == "__main__":
    multiprocessing.freeze_support()
    from packetbreaker.cli import main

    # Native dependencies are imported above. External tshark must use its own libraries,
    # rather than inherit the bootloader's Windows DLL directory or hook-added paths.
    if getattr(sys, "frozen", False):
        if sys.platform == "win32":
            import ctypes

            ctypes.windll.kernel32.SetDllDirectoryW(None)
        for name in ("PATH", "DYLD_LIBRARY_PATH"):
            if name in os.environ:
                os.environ[name] = os.pathsep.join(
                    item
                    for item in os.environ[name].split(os.pathsep)
                    if not os.path.abspath(item).startswith(sys._MEIPASS + os.sep)
                    and os.path.abspath(item) != sys._MEIPASS
                )
    main()
