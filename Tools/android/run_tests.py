#!/usr/bin/env python3
"""Runs RHP's test executables on an Android device or emulator through adb.

    python Tools/android/run_tests.py build/android-arm64-tests            # Debug, the only device
    python Tools/android/run_tests.py build/android-x64 --serial emulator-5554 --config Release

Every Catch2 suite (rhp_*_tests) and fuzz replay driver (rhp_fuzz_*_replay) of the build goes to
/data/local/tmp/rhp-tests on the device and runs there (TMPDIR points inside it); the folder is
removed afterwards unless --keep. Exit status: 0 when every executable passed.
"""

import argparse
import pathlib
import subprocess
import sys

REMOTE = "/data/local/tmp/rhp-tests"
ADB_RETRIES = 2  # runs of one executable after an adb shell session drops


def adb(serial, *args, check=True, capture=False):
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    return subprocess.run(cmd, check=check, text=True, capture_output=capture, encoding="utf-8", errors="replace")


def executables(build, config):
    found = []
    for path in sorted(pathlib.Path(build, "Tests").rglob("*")):
        if not path.is_file() or path.suffix or path.parent.name != config:
            continue
        if (path.name.startswith("rhp_") and path.name.endswith("_tests")) or (path.name.startswith("rhp_fuzz_") and path.name.endswith("_replay")):
            found.append(path)
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("build", help="the Android build directory (configured with RHP_BUILD_TESTS=ON)")
    parser.add_argument("--config", default="Debug")
    parser.add_argument("--serial", default=None, help="adb device serial (default: the only device)")
    parser.add_argument("--keep", action="store_true", help="leave the files on the device")
    args = parser.parse_args()

    exes = executables(args.build, args.config)
    if not exes:
        print(f"no test executables under {args.build}/Tests/**/{args.config}", file=sys.stderr)
        return 2
    abi = adb(args.serial, "shell", "getprop", "ro.product.cpu.abi", capture=True).stdout.strip()
    model = adb(args.serial, "shell", "getprop", "ro.product.model", capture=True).stdout.strip()
    sdk = adb(args.serial, "shell", "getprop", "ro.build.version.sdk", capture=True).stdout.strip()
    print(f"device: {model} ({abi}, API {sdk}); {len(exes)} executables")

    adb(args.serial, "shell", f"rm -rf {REMOTE} && mkdir -p {REMOTE}/tmp")
    failed = []
    try:
        for exe in exes:
            adb(args.serial, "push", str(exe), f"{REMOTE}/{exe.name}", capture=True)
            extra = " --iterations 3000" if exe.name.endswith("_replay") else ""
            command = f"cd {REMOTE} && chmod 755 {exe.name} && TMPDIR={REMOTE}/tmp HOME={REMOTE}/tmp ./{exe.name}{extra}; echo RHP_EXIT=$?"
            for attempt in range(1 + ADB_RETRIES):
                run = adb(args.serial, "shell", command, check=False, capture=True)
                out = run.stdout
                if "RHP_EXIT=" in out:
                    break
                # No exit marker: the adb shell session itself dropped (the shell prints the marker
                # even after the executable crashes). Run it again rather than report a test failure.
                print(f"  {exe.name}: adb shell returned no exit status (adb exit {run.returncode}: {run.stderr.strip()[-200:]}); "
                      f"{'retrying' if attempt < ADB_RETRIES else 'giving up'}")
            code = out.rsplit("RHP_EXIT=", 1)[-1].strip() if "RHP_EXIT=" in out else "?"
            summary = [line for line in out.splitlines() if "test cases" in line or "All tests passed" in line or line.startswith("ran ")]
            status = "ok" if code == "0" else f"FAILED ({code})"
            print(f"  {exe.name}: {status} {summary[-1].strip() if summary else ''}")
            if code != "0":
                failed.append(exe.name)
                print(out[-4000:])
    finally:
        if not args.keep:
            adb(args.serial, "shell", f"rm -rf {REMOTE}", check=False)
    print("all passed" if not failed else f"{len(failed)} failed: {', '.join(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
