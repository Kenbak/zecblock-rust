"""Audit the lockfile; permit listed advisories only while absent from every compiled target."""
import subprocess

# Cargo locks the optional drivers of SQLx even when they are disabled: MySQL
# brings RSA and SQLite brings libsqlite3-sys. This PostgreSQL-only binary
# disables SQLx default features, so neither is built. Never silently carry
# these exceptions into a build that enables one; the graph check below fails.
UNCOMPILED_EXCEPTIONS = {
    "rsa": "RUSTSEC-2023-0071",
    "libsqlite3-sys": "RUSTSEC-2026-0459",
}

graph = subprocess.check_output(
    ["cargo", "tree", "--locked", "--target", "all", "--edges", "normal,build",
     "--prefix", "none", "--format", "{p}"], text=True
)
compiled = graph.splitlines()
for crate, advisory in UNCOMPILED_EXCEPTIONS.items():
    if any(line.startswith(f"{crate} v") for line in compiled):
        raise SystemExit(f"{crate} entered the compiled graph; remove it or resolve {advisory}")

ignored = [arg for advisory in UNCOMPILED_EXCEPTIONS.values() for arg in ("--ignore", advisory)]
subprocess.run(["cargo", "audit", "--deny", "unsound", *ignored], check=True)
