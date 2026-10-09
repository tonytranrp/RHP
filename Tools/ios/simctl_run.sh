#!/bin/sh
# CMAKE_CROSSCOMPILING_EMULATOR of the ios-sim preset: runs an iOS-simulator executable (a test, or
# Catch2's test discovery) on a booted simulator. RHP_SIM_DEVICE picks one (default: the booted one).
# The child gets this side's TMPDIR, so tests that write temporary files find a writable folder.
export SIMCTL_CHILD_TMPDIR="${TMPDIR:-/tmp}"
exec xcrun simctl spawn "${RHP_SIM_DEVICE:-booted}" "$@"
