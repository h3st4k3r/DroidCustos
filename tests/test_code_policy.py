import ast
import io
import tokenize
from pathlib import Path


def test_function_docstrings_and_comment_policy():
    """Enforce brief function-start documentation and no inline comments."""
    for path in Path("droidcustos").glob("*.py"):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                assert ast.get_docstring(node), f"Missing function docstring: {path}:{node.lineno}"
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        comments = [token for token in tokens if token.type == tokenize.COMMENT]
        assert not comments, f"Inline comments are not allowed: {path}"
