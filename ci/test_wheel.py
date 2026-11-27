"""Test the actual distribution outside the checkout, with or without extras."""
from pathlib import Path
import os
import subprocess
import tempfile
import venv

root = Path(__file__).resolve().parents[1]
wheels = list((root / 'packages').glob('*.whl'))
if len(wheels) != 1:
    raise ValueError('expected exactly one wheel')
signing = os.environ.get('TAILMETA_TEST_SIGNING', 'no') == 'yes'
with tempfile.TemporaryDirectory(prefix='tailmeta-wheel-') as directory:
    directory = Path(directory)
    venv.create(directory / 'venv', with_pip=True)
    python = directory / 'venv/bin/python'
    package = str(wheels[0]) + ('[signing]' if signing else '')
    subprocess.run([str(python), '-m', 'pip', 'install', package], check=True, cwd=directory)
    subprocess.run([str(python), '-c', f'import importlib.util; assert bool(importlib.util.find_spec("cryptography")) == {signing!r}'], check=True, cwd=directory)
    subprocess.run([str(python), '-m', 'unittest', 'discover', '-s', str(root / 'tests'), '-v'], check=True, cwd=directory)
    subprocess.run([str(directory / 'venv/bin/tailmeta'), '--version'], check=True, cwd=directory)
