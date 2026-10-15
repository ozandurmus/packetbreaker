import sys
from types import ModuleType
from packetbreaker.store import cache_missing_pandas


def test_existing_pandas_is_never_replaced(monkeypatch):
    present = ModuleType("pandas")
    monkeypatch.setitem(sys.modules, "pandas", present)
    cache_missing_pandas()
    assert sys.modules["pandas"] is present


def test_absent_optional_import_is_not_repeated_per_sql_parameter(monkeypatch):
    import duckdb
    import importlib.util

    monkeypatch.delitem(sys.modules, "pandas", raising=False)
    original = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util, "find_spec", lambda name: None if name == "pandas" else original(name)
    )
    cache_missing_pandas()
    calls = []

    class Probe:
        def find_spec(self, name, path=None, target=None):
            if name == "pandas":
                calls.append(name)

    probe = Probe()
    sys.meta_path.insert(0, probe)
    try:
        with duckdb.connect() as db:
            for n in range(20):
                assert db.execute("SELECT ?::VARCHAR,?::BIGINT", [str(n), n]).fetchone() == (str(n), n)
        assert calls == []
    finally:
        sys.meta_path.remove(probe)


SYNTHETIC_MODULES = {
    "attribution_synthetic",
    "diagnostic_synthetic",
    "integrity_synthetic",
    "offload_synthetic",
    "onset_synthetic",
    "pilot_synthetic",
    "realistic",
    "security_synthetic",
    "session_synthetic",
    "synthetic",
    "translation_synthetic",
    "voip_synthetic",
}


def _module_name(root, path):
    rel = path.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _find_cycles(graph):
    cycles = []
    for start in sorted(graph):
        stack = [(start, [start])]
        visited = set()
        while stack:
            cur, path = stack.pop()
            for nxt in sorted(graph.get(cur, ())):
                if nxt == start:
                    cycles.append(path + [start])
                elif nxt not in path and nxt not in visited:
                    visited.add(nxt)
                    stack.append((nxt, path + [nxt]))
    return cycles


def test_no_circular_imports_or_synthetic_imports_in_production():
    import ast
    import importlib
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "packetbreaker"
    py_files = sorted(root.rglob("*.py"))
    known = {_module_name(root, p) for p in py_files if _module_name(root, p)}
    production = known - SYNTHETIC_MODULES

    edges = {}
    forbidden_imports = []

    for path in py_files:
        mod = _module_name(root, path)
        if mod not in production:
            continue
        edges[mod] = set()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        demo_exempt_nodes = set()
        if mod == "cli":
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.If)
                    and isinstance(node.test, ast.Compare)
                    and isinstance(node.test.left, ast.Attribute)
                    and node.test.left.attr == "command"
                    and any(isinstance(c, ast.Constant) and c.value == "demo" for c in node.test.comparators)
                ):
                    for child in ast.walk(node):
                        demo_exempt_nodes.add(child)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in ("tests", "pytest", "conftest"):
                        forbidden_imports.append((mod, alias.name))
                    if alias.name.startswith("packetbreaker."):
                        sub = alias.name.removeprefix("packetbreaker.")
                        if sub.split(".")[0] in SYNTHETIC_MODULES and node not in demo_exempt_nodes:
                            forbidden_imports.append((mod, sub))
                        if sub in production and sub != mod:
                            edges[mod].add(sub)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    top = node.module.split(".")[0]
                    if top in ("tests", "pytest", "conftest"):
                        forbidden_imports.append((mod, node.module))
                if node.level > 0:
                    base_parts = list(path.relative_to(root).parts[:-1])
                    if node.level > 1:
                        base_parts = base_parts[: -(node.level - 1)]
                    target = ".".join(base_parts + ([node.module] if node.module else []))
                elif node.module and node.module.startswith("packetbreaker."):
                    target = node.module.removeprefix("packetbreaker.")
                else:
                    continue

                resolved = set()
                for alias in node.names:
                    cand = f"{target}.{alias.name}" if target else alias.name
                    if cand in known:
                        resolved.add(cand)
                if not resolved and target in known:
                    resolved.add(target)

                for r in resolved:
                    if r.split(".")[0] in SYNTHETIC_MODULES and node not in demo_exempt_nodes:
                        forbidden_imports.append((mod, r))
                    elif r in production and r != mod:
                        edges[mod].add(r)

    assert forbidden_imports == [], f"Production code imports synthetic/test modules: {forbidden_imports}"
    assert _find_cycles(edges) == [], f"Circular imports detected in production graph: {_find_cycles(edges)}"
    assert _find_cycles({"a": {"b"}, "b": {"a"}}) != []

    # Verify isolated runtime import in both orders without loading any synthetic module
    for order in (sorted(production), sorted(production, reverse=True)):
        for k in [
            k
            for k in list(sys.modules)
            if k == "packetbreaker" or k.startswith("packetbreaker.")
        ]:
            del sys.modules[k]
        for mod in order:
            importlib.import_module(f"packetbreaker.{mod}")
        loaded_synth = [
            s for s in SYNTHETIC_MODULES if f"packetbreaker.{s}" in sys.modules
        ]
        assert loaded_synth == [], f"Importing production modules loaded synthetic modules: {loaded_synth}"


def test_refactored_packages_respect_module_and_function_size_limits():
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "src" / "packetbreaker"
    for pkg in ("analysis", "topology", "integrity"):
        pkg_files = sorted((root / pkg).glob("*.py"))
        assert len(pkg_files) >= 5
        for path in pkg_files:
            source = path.read_text(encoding="utf-8")
            line_count = len(source.splitlines())
            assert line_count <= 500, f"{path.relative_to(root)} has {line_count} lines (> 500)"
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn_lines = node.end_lineno - node.lineno + 1
                    assert fn_lines <= 120, (
                        f"{path.relative_to(root)}:{node.name} has {fn_lines} lines (> 120)"
                    )

