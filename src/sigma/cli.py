"""CLI for Sigma validation/conversion/import."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..database import CyberionDB
from ..alerts.manager import AlertManager
from .importer import SigmaRuleImporter


def _make_importer() -> SigmaRuleImporter:
    db = CyberionDB()
    return SigmaRuleImporter(db.alerts)


def _print_results(results):
    for idx, result in enumerate(results, start=1):
        payload = {
            "index": idx,
            "status": result.status.value,
            "sigma_id": result.sigma_id,
            "sigma_title": result.sigma_title,
            "local_rule_id": result.local_rule_id,
            "errors": result.errors,
            "warnings": result.warnings,
        }
        print(json.dumps(payload, ensure_ascii=False))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Cyberion Sigma importer")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate", help="Validate Sigma YAML without importing")
    validate.add_argument("path", help="Sigma file path")

    convert = sub.add_parser("convert", help="Convert Sigma YAML and preview statuses")
    convert.add_argument("path", help="Sigma file path")

    imp = sub.add_parser("import", help="Import Sigma file or directory")
    imp.add_argument("path", help="Sigma file or directory")
    imp.add_argument("--update-existing", action="store_true", help="Update existing Sigma ID mappings")

    args = parser.parse_args(argv)

    importer = _make_importer()
    if args.command == "validate":
        results = importer.validate_file(args.path)
        _print_results(results)
        return

    if args.command == "convert":
        results = importer.convert_file(args.path)
        _print_results(results)
        return

    if args.command == "import":
        results = importer.import_path(args.path, update_existing=args.update_existing)
        _print_results(results)
        return


if __name__ == "__main__":
    main()
