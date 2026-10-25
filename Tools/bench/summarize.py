#!/usr/bin/env python3
"""Turns rhp_bench's Catch2 XML report into a Markdown table.

    rhp_bench "[bench]" --reporter xml::out=bench.xml --benchmark-samples 100
    python Tools/bench/summarize.py bench.xml > bench.md

Benchmarks are named "<group> <side>: <work>", side being raw (plain Lua / C++), rhp, local or
unchecked (a sandbox with limits.cancel_checks = kNone).
A raw benchmark and an rhp benchmark of the same group and work are twins: the table shows the
rhp mean as a multiple of the raw one (the overhead RHP adds to that work).
"""
import argparse
import re
import sys
import xml.etree.ElementTree as ET

NAME = re.compile(r"^(?P<group>\S+) (?P<side>raw|rhp|local|unchecked): (?P<work>.+)$")


def load(path):
    """Returns [(name, mean_ns, low_ns, high_ns, stddev_ns)] in report order."""
    rows = []
    for result in ET.parse(path).getroot().iter("BenchmarkResults"):
        mean = result.find("mean")
        stddev = result.find("standardDeviation")
        if mean is None:  # a benchmark that failed or was skipped
            continue
        rows.append((
            result.get("name"),
            float(mean.get("value")),
            float(mean.get("lowerBound")),
            float(mean.get("upperBound")),
            float(stddev.get("value")) if stddev is not None else 0.0,
        ))
    return rows


def human(ns):
    for unit, scale in (("s", 1e9), ("ms", 1e6), ("us", 1e3)):
        if ns >= scale:
            return f"{ns / scale:.3g} {unit}"
    return f"{ns:.3g} ns"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", help="Catch2 XML report of rhp_bench")
    parser.add_argument("--title", default="", help="heading printed above the table")
    args = parser.parse_args()

    rows = load(args.report)
    raw = {}
    for name, mean, *_ in rows:
        m = NAME.match(name)
        if m and m["side"] == "raw":
            raw[(m["group"], m["work"])] = mean

    if args.title:
        print(f"### {args.title}\n")
    print("| Benchmark | Mean | 95% CI | Std dev | x raw |")
    print("|---|---:|---:|---:|---:|")
    for name, mean, low, high, stddev in rows:
        m = NAME.match(name)
        ratio = ""
        if m and m["side"] != "raw" and (m["group"], m["work"]) in raw:
            ratio = f"{mean / raw[(m['group'], m['work'])]:.2f}"
        print(f"| {name} | {human(mean)} | {human(low)} - {human(high)} | {human(stddev)} | {ratio} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
