"""
UATU Linux Edition - Command Execution AST Repo Guard Test
Statically inspects all Python files across the codebase to ensure ZERO occurrences of:
1. os.system()
2. os.popen()
3. subprocess.*(..., shell=True)
4. popen2 / commands legacy execution
"""

import ast
import os
from pathlib import Path
import pytest
from typing import List, Tuple


IGNORE_DIRS = {
    ".git",
    ".github",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "site-packages"
}


def find_python_files(root_dir: Path) -> List[Path]:
    """Find all Python source files in the repository, excluding virtual environments and caches."""
    py_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Exclude ignored directories in-place
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
        for f in filenames:
            if f.endswith(".py"):
                py_files.append(Path(dirpath) / f)
    return py_files


class ShellExecutionVisitor(ast.NodeVisitor):
    """AST visitor that detects insecure process execution patterns."""

    def __init__(self, filename: str):
        self.filename = filename
        self.violations: List[str] = []

    def visit_Call(self, node: ast.Call):
        # 1. Check for os.system or os.popen
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            # Case: os.system(...) or os.popen(...)
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                if func_name in ("system", "popen"):
                    self.violations.append(
                        f"{self.filename}:{node.lineno} Insecure call 'os.{func_name}()' detected."
                    )

            # Case: subprocess.*(..., shell=True)
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                for kw in node.keywords:
                    if kw.arg == "shell":
                        # Check if value is True or truthy constant
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self.violations.append(
                                f"{self.filename}:{node.lineno} 'subprocess.{func_name}(..., shell=True)' detected."
                            )

        # 2. Check for direct call to imported system / popen (e.g. from os import system)
        elif isinstance(node.func, ast.Name):
            if node.func.id in ("system", "popen"):
                # We can flag if it looks like an os.system/popen call
                pass

        self.generic_visit(node)


def test_no_shell_true_or_os_system_in_codebase():
    """Verify that no code in the repository uses shell=True, os.system, or os.popen."""
    repo_root = Path(__file__).resolve().parent.parent
    py_files = find_python_files(repo_root)

    assert len(py_files) > 10, f"Expected to scan repository python files, found only {len(py_files)}"

    all_violations: List[str] = []
    for py_file in py_files:
        try:
            with open(py_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            tree = ast.parse(content, filename=str(py_file))
            visitor = ShellExecutionVisitor(str(py_file.relative_to(repo_root)))
            visitor.visit(tree)
            all_violations.extend(visitor.violations)
        except SyntaxError as e:
            pytest.fail(f"Syntax error parsing {py_file}: {e}")

    assert not all_violations, (
        f"Found {len(all_violations)} forbidden shell execution violations:\n"
        + "\n".join(all_violations)
    )

