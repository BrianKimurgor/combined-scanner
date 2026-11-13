from typing import Any

from scanner.normalize import severity
from scanner.normalize.finding import Category, Finding
from scanner.plugins.base import (
    CommandResult,
    Parsed,
    ScanContext,
    ScannerPlugin,
    load_json,
    rel_path,
    to_line,
)

# Programming languages only: JSON, SQL, Markdown and lockfiles repeat by nature, not by neglect.
CODE_FORMATS = (
    "javascript,jsx,typescript,tsx,vue,svelte,astro,python,java,kotlin,scala,groovy,go,rust,"
    "c,c-header,cpp,cpp-header,csharp,fsharp,php,ruby,swift,objectivec,dart,lua,perl,r,bash,"
    "elixir,haskell,clojure,ocaml,solidity"
)


class JscpdPlugin(ScannerPlugin):
    name = "jscpd"
    binary = "jscpd"

    def build_command(self, ctx: ScanContext) -> list[str]:
        command = [
            "jscpd",
            ".",
            "--reporters",
            "json",
            "--output",
            str(ctx.plugin_dir(self.name)),
            "--format",
            CODE_FORMATS,
            "--silent",
        ]
        ignore = [*ctx.config.ignore, *ctx.config.quality_ignore]
        if ignore:
            command += ["--ignore", ",".join(ignore)]
        return command

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        report = ctx.plugin_dir(self.name) / "jscpd-report.json"
        if not report.is_file():
            return Parsed([])
        data = load_json(report.read_text(encoding="utf-8"), {})
        # One finding per file: a few thousand individual clone blocks are unreadable noise.
        blocks: dict[str, list[dict[str, Any]]] = {}
        for clone in data.get("duplicates") or []:
            name = rel_path(str(clone["firstFile"]["name"]), ctx.workdir)
            blocks.setdefault(name, []).append(clone)
        findings = [self._finding(ctx, name, clones) for name, clones in blocks.items()]
        percent = data.get("statistics", {}).get("total", {}).get("percentage")
        metrics = {"duplication_percent": float(percent)} if percent is not None else {}
        return Parsed(findings, metrics)

    def _finding(self, ctx: ScanContext, name: str, clones: list[dict[str, Any]]) -> Finding:
        largest = max(clones, key=lambda c: int(c.get("lines") or 0))
        first, second = largest["firstFile"], largest["secondFile"]
        other = f"{rel_path(str(second['name']), ctx.workdir)}:{second.get('start')}"
        if len(clones) == 1:
            title = f"{largest.get('lines', '?')} duplicated lines"
            message = f"Block is duplicated at {other}"
        else:
            total = sum(int(c.get("lines") or 0) for c in clones)
            title = f"{len(clones)} duplicated blocks ({total} lines)"
            message = f"Largest block ({largest.get('lines', '?')} lines) is duplicated at {other}"
        return Finding(
            tool=self.name,
            category=Category.DUPLICATION,
            rule_id="duplicated-code",
            severity=severity.DUPLICATION,
            title=title,
            message=message,
            file=name,
            line_start=to_line(first.get("start")),
            line_end=to_line(first.get("end")),
        )
