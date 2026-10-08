"""Package the two CI binaries as public release downloads."""

import argparse
import hashlib
from pathlib import Path
import re
import tarfile
import zipfile


def package(inputs: Path, output: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    version = (root / "VERSION").read_text().strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid VERSION")
    windows = inputs / "totpvault-Windows-amd64" / "totpvault.exe"
    linux = inputs / "totpvault-Linux-amd64" / "totpvault"
    for binary, magic in ((windows, b"MZ"), (linux, b"\x7fELF")):
        with binary.open("rb") as stream:
            if stream.read(len(magic)) != magic:
                raise ValueError(f"Unexpected executable format: {binary}")
    docs = [root / name for name in ("LICENSE", "README.md", "SECURITY.md")]
    output.mkdir(parents=True, exist_ok=True)
    windows_zip = output / f"totpvault-v{version}-windows-amd64.zip"
    with zipfile.ZipFile(windows_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        for source in [windows, *docs]:
            archive.write(source, source.name)
    linux_tar = output / f"totpvault-v{version}-linux-amd64.tar.gz"
    with tarfile.open(linux_tar, "w:gz") as archive:
        for source in [linux, *docs]:
            info = archive.gettarinfo(str(source), arcname=source.name)
            info.mode = 0o755 if source == linux else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with source.open("rb") as stream:
                archive.addfile(info, stream)
    checksums = []
    for asset in sorted([windows_zip, linux_tar]):
        with asset.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        checksums.append(f"{digest}  {asset.name}\n")
    (output / "SHA256SUMS").write_text("".join(checksums))
    print("Packaged Windows ZIP, Linux tar.gz and SHA256SUMS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    package(args.inputs, args.output)
