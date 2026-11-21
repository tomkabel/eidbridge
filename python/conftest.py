"""Make the package importable when the tests run from a checkout."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
