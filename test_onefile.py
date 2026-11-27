"""Sign and verify a disposable copy of the actual compiled onefile."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from tailmeta._core import FOOTER, MAGIC, encode_metadata, read_metadata


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def cli(*args, success=True):
    result = subprocess.run([sys.executable, '-m', 'tailmeta', *map(str, args)], capture_output=True, text=True, timeout=60)
    check((result.returncode == 0) == success, result.stdout + result.stderr)
    return result.stdout


def run(path, expected=None, verify_signature=True):
    env = os.environ.copy()
    env.pop('NUITKA_ONEFILE_BINARY', None)
    command = [str(path)]
    if verify_signature:
        command += ["--public-key", str(path) + ".pub.pem"]
    result = subprocess.run(command, cwd=path.parent, env=env, capture_output=True, text=True, timeout=60)
    if expected is None:
        check(result.returncode != 0 and 'verification failed:' in result.stderr, result.stdout + result.stderr)
    else:
        check(result.returncode == 0 and result.stdout.strip() == f'version={expected}', result.stdout + result.stderr)


source = Path(sys.argv[1]).resolve()
base = source.read_bytes()
check(read_metadata(source) is None, 'requires a fresh unstamped build')
with tempfile.TemporaryDirectory(prefix='onefile-test-') as directory:
    binary = Path(directory) / 'app with spaces'
    private = Path(directory) / 'private.pem'
    public = Path(str(binary) + '.pub.pem')
    shutil.copy2(source, binary)
    run(binary, 'unknown', verify_signature=False)
    cli('stamp', binary, '--version', '0.1.0')
    run(binary, '0.1.0', verify_signature=False)
    binary.write_bytes(base)
    print('PASS: unsigned stamp and read without keys')
    cli('keygen', '--private-key', private, '--public-key', public)
    run(binary)
    print('PASS: unsigned binary rejected')
    for version in ('1.2.4', '2.0', '3.0.0'):
        cli('stamp', binary, '--version', version, '--channel', 'тест' * 100, '--private-key', private)
        cli('verify', binary, '--public-key', public)
        metadata = read_metadata(binary)
        check(metadata['sha256'] == hashlib.sha256(base).hexdigest(), 'hash mismatch')
        data = encode_metadata(metadata)
        check(binary.read_bytes() == base + data + FOOTER.pack(len(data), MAGIC), 'payload changed or trailers accumulated')
        run(binary, version)
        print(f'PASS: signed {version}, verified outside/inside, original bytes preserved')
    signed = binary.read_bytes()
    binary.write_bytes(signed.replace(b'"version":"3.0.0"', b'"version":"9.9.9"'))
    cli('verify', binary, '--public-key', public, success=False)
    run(binary)
    print('PASS: altered metadata rejected outside/inside')
    binary.write_bytes(b'X' + signed[1:])
    cli('verify', binary, '--public-key', public, success=False)
    print('PASS: altered binary rejected externally (not executed)')
    binary.write_bytes(signed)
    correct_key = public.read_bytes()
    public.unlink()
    run(binary)
    print('PASS: missing public key rejected inside')
    cli('keygen', '--private-key', private.with_name('wrong.pem'), '--public-key', public)
    cli('verify', binary, '--public-key', public, success=False)
    run(binary)
    print('PASS: wrong public key rejected outside/inside')
    public.write_bytes(correct_key)
    binary.write_bytes(base)
    cli('verify', binary, '--public-key', public, success=False)
    run(binary)
    print('PASS: stripped trailer rejected outside/inside')
check(source.read_bytes() == base, 'original build modified')
