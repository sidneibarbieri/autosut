"""Validate local dashboard links against the served artifact root."""

from __future__ import annotations

import argparse
import json
from html.parser import HTMLParser
from pathlib import Path
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict


class DashboardLinkIssue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    reference: str
    reason: Literal[
        "outside_artifact", "missing_file", "missing_anchor", "unsupported_scheme"
    ]


class DashboardReferences(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.references: set[str] = set()
        self.anchors: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if attributes.get("id"):
            self.anchors.add(attributes["id"])
        attribute = "href" if tag in {"a", "link"} else "src"
        if tag in {"a", "link", "img", "script"} and attributes.get(attribute):
            self.references.add(attributes[attribute])


def audit_links(dashboard: Path, artifact_root: Path) -> list[DashboardLinkIssue]:
    artifact_root = artifact_root.resolve(strict=True)
    dashboard = dashboard.resolve(strict=True)
    if not dashboard.is_relative_to(artifact_root):
        raise ValueError("Dashboard must be inside the artifact root.")
    page = DashboardReferences()
    page.feed(dashboard.read_text(encoding="utf-8"))
    issues = []
    for reference in sorted(page.references):
        address = urlsplit(reference)
        if address.scheme in {"http", "https", "mailto"} or address.netloc:
            continue
        reason = None
        if address.scheme:
            reason = "unsupported_scheme"
        elif not address.path:
            if address.fragment and unquote(address.fragment) not in page.anchors:
                reason = "missing_anchor"
        else:
            path = unquote(address.path)
            target = (
                (artifact_root / path.lstrip("/"))
                if path.startswith("/")
                else (dashboard.parent / path)
            ).resolve()
            if not target.is_relative_to(artifact_root):
                reason = "outside_artifact"
            elif not target.is_file():
                reason = "missing_file"
        if reason is not None:
            issues.append(DashboardLinkIssue(reference=reference, reason=reason))
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--dashboard", type=Path, default=Path("release/dashboard/index.html")
    )
    args = parser.parse_args()
    dashboard = (
        args.dashboard if args.dashboard.is_absolute() else args.root / args.dashboard
    )
    issues = audit_links(dashboard, args.root)
    print(
        json.dumps(
            {
                "status": "failed" if issues else "pass",
                "issue_count": len(issues),
                "issues": [issue.model_dump() for issue in issues],
            },
            indent=2,
        )
    )
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
