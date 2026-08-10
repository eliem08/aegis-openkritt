"""Aegis operator command line."""

from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis")
    commands = parser.add_subparsers(dest="command", required=True)
    production = commands.add_parser("production")
    production_commands = production.add_subparsers(dest="production_command", required=True)
    health = production_commands.add_parser("health")
    health.add_argument("--json", dest="json_path")
    args = parser.parse_args(argv)
    if args.command == "production" and args.production_command == "health":
        from aegis.production.health import main as health_main

        health_args = ["--json", args.json_path] if args.json_path else []
        return health_main(health_args)
    parser.error("unsupported command")
    return 2
