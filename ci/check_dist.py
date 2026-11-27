"""Validate release tags and metadata before granting publishing permissions."""
from email.parser import BytesParser
from pathlib import Path
import os
import re
import tarfile
import zipfile


def check(directory=Path('packages'), ref=None):
    wheels = list(directory.glob('*.whl'))
    sdists = list(directory.glob('*.tar.gz'))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError('expected exactly one wheel and one sdist')
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        metadata_names = [n for n in names if n.endswith('.dist-info/METADATA')]
        if len(metadata_names) != 1:
            raise ValueError('expected one wheel metadata record')
        wheel = BytesParser().parsebytes(archive.read(metadata_names[0]))
        if not all(n.startswith(('tailmeta/', 'tailmeta-')) for n in names):
            raise ValueError('unexpected wheel contents')
    with tarfile.open(sdists[0]) as archive:
        members = [m for m in archive.getmembers() if m.name.count('/') == 1 and m.name.endswith('/PKG-INFO')]
        if len(members) != 1:
            raise ValueError('expected one sdist metadata record')
        sdist = BytesParser().parsebytes(archive.extractfile(members[0]).read())
        if any(m.name.endswith('.pem') for m in archive.getmembers()):
            raise ValueError('key file included in sdist')
    if wheel['Name'] != 'tailmeta' or sdist['Name'] != 'tailmeta' or wheel['Version'] != sdist['Version']:
        raise ValueError('inconsistent distribution metadata')
    ref = os.environ.get('GITHUB_REF', '') if ref is None else ref
    if ref.startswith('refs/tags/'):
        tag = ref.removeprefix('refs/tags/')
        if not re.fullmatch(r'v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:(?:a|b|rc)(0|[1-9]\d*))?', tag):
            raise ValueError('release tag must be vX.Y.Z (optional aN, bN or rcN suffix)')
        if wheel['Version'] != tag[1:]:
            raise ValueError(f"tag {tag} does not match package version {wheel['Version']}")
    print(f"Validated tailmeta {wheel['Version']} wheel and sdist")


if __name__ == '__main__':
    check()
