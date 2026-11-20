#!/usr/bin/env python3
"""Package every publishable crate and test the extracted artifact.

`cargo publish --dry-run` cannot verify a crate whose workspace sibling is not
on crates.io yet. That is the release engine's normal state: the BuildKit crate
is uploaded seconds before the engine that names it. This script closes that
gap without touching the index.

For each row in `packages.tsv` it:

1. packages the crate with `--no-verify`, patching workspace siblings to their
   source directories only so cargo can resolve the manifest;
2. extracts the resulting `.crate` into an isolated directory; and
3. runs `cargo test --all-targets --all-features` from the extracted source,
   patching every workspace sibling to the extracted sibling.

The last step is the point. The tests run against the files that will ship,
including crate-local fixtures, not against the checkout that happens to sit
beside them. `packages.tsv` is written by `.github/actions/package-order`.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGES = ROOT / "packages.tsv"


def fail(message: str) -> None:
    print(f"package preflight: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_packages() -> list[dict[str, str]]:
    if not PACKAGES.is_file():
        fail(
            "packages.tsv is missing; run the package-order action or "
            "`cargo metadata --no-deps --format-version 1` first"
        )

    rows = []
    for number, line in enumerate(PACKAGES.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 4:
            fail(f"packages.tsv line {number} does not have four fields")
        name, version, manifest, deps = fields
        directory = Path(manifest).resolve().parent
        if not (directory / "Cargo.toml").is_file():
            fail(f"{name}: manifest directory {directory} has no Cargo.toml")
        rows.append(
            {
                "name": name,
                "version": version,
                "directory": str(directory),
                "deps": [dep for dep in deps.split(",") if dep],
            }
        )

    if not rows:
        fail("packages.tsv lists no publishable package")
    return rows


def run(command: list[str], cwd: Path, env: dict[str, str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def patch_args(dependencies: list[str], paths: dict[str, Path]) -> list[str]:
    args = []
    for name in dependencies:
        args.extend(["--config", f'patch.crates-io.{name}.path="{paths[name]}"'])
    return args


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="pass --allow-dirty to cargo package (local runs only)",
    )
    args = parser.parse_args()

    rows = read_packages()
    names = [row["name"] for row in rows]
    by_name = {row["name"]: row for row in rows}

    env = os.environ.copy()
    env.setdefault("CARGO_TERM_COLOR", "always")

    with tempfile.TemporaryDirectory(prefix="neotales-package-preflight-") as temporary:
        temporary_path = Path(temporary)
        extracted: dict[str, Path] = {}
        # Reuse the workspace target directory rather than a second full build
        # tree. The extracted crate paths keep cargo's fingerprints distinct.
        env["CARGO_TARGET_DIR"] = str(ROOT / "target")

        for row in rows:
            name = row["name"]
            version = row["version"]
            package_command = [
                "cargo",
                "package",
                "-p",
                name,
                "--no-verify",
                "--locked",
            ]
            if args.allow_dirty:
                package_command.append("--allow-dirty")
            package_command.extend(
                patch_args(
                    row["deps"],
                    {dep: Path(by_name[dep]["directory"]) for dep in names},
                )
            )
            run(package_command, ROOT, env)

            crate = ROOT / "target" / "package" / f"{name}-{version}.crate"
            if not crate.is_file():
                fail(f"{name}: cargo package did not write {crate}")

            destination = temporary_path / name
            destination.mkdir()
            with tarfile.open(crate) as archive:
                archive.extractall(destination)

            source = destination / f"{name}-{version}"
            if not (source / "Cargo.toml").is_file():
                fail(f"{name}: extracted crate has no Cargo.toml")
            extracted[name] = source

        for row in rows:
            name = row["name"]
            # No `--locked` here: the extracted Cargo.lock does not know the
            # patch paths, and the lock belongs to a disposable copy.
            command = [
                "cargo",
                "test",
                "--all-targets",
                "--all-features",
            ]
            command.extend(patch_args(row["deps"], extracted))
            run(command, extracted[name], env)

    print(f"package preflight passed for {len(rows)} crates: {', '.join(names)}")


if __name__ == "__main__":
    main()
