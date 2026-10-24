#!/usr/bin/env python3
"""Compares two rhp_bench Catch2 XML reports (before / after a change) as a Markdown table.

    python Tools/bench/compare.py before.xml after.xml [--threshold 5]

A change counts only when the confidence intervals don't overlap and the means differ by more
than --threshold percent; everything else is reported as noise ("~").
"""
import argparse
import sys

from summarize import human, load


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--threshold", type=float, default=5.0, help="smallest change (percent) worth reporting")
    args = parser.parse_args()

    before = {name: (mean, low, high) for name, mean, low, high, _ in load(args.before)}
    after = load(args.after)

    print("| Benchmark | Before | After | Change |")
    print("|---|---:|---:|---:|")
    for name, mean, low, high, _ in after:
        if name not in before:
            print(f"| {name} | - | {human(mean)} | new |")
            continue
        b_mean, b_low, b_high = before[name]
        change = (mean - b_mean) / b_mean * 100.0
        overlap = low <= b_high and b_low <= high
        verdict = "~" if overlap or abs(change) < args.threshold else f"{change:+.1f}%"
        print(f"| {name} | {human(b_mean)} | {human(mean)} | {verdict} |")
    for name in before.keys() - {row[0] for row in after}:
        print(f"| {name} | {human(before[name][0])} | - | gone |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
