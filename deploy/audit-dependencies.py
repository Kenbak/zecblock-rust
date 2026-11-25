"""Audit the lockfile; permit listed advisories only while absent from every compiled target."""
import subprocess

# Cargo locks the optional drivers of SQLx even when they are disabled: MySQL
# brings RSA and SQLite brings libsqlite3-sys. This PostgreSQL-only binary
# disables SQLx default features, so neither is built. Never silently carry
# these exceptions into a build that enables one; the graph check below fails.
UNCOMPILED_EXCEPTIONS = {
    "rsa": ["RUSTSEC-2023-0071"],
    "libsqlite3-sys": ["RUSTSEC-2026-0459"],
    # postcard (via zakura-chain's FROST/reddsa crates) locks heapless 0.7 for
    # its optional `heapless` feature, which nothing here enables. The 2026-11-18
    # heapless unsoundness advisories are fixed only in 0.9.4+.
    "heapless": [
        "RUSTSEC-2026-0574", "RUSTSEC-2026-0575", "RUSTSEC-2026-0576",
        "RUSTSEC-2026-0577", "RUSTSEC-2026-0578", "RUSTSEC-2026-0579",
        "RUSTSEC-2026-0580", "RUSTSEC-2026-0581", "RUSTSEC-2026-0582",
    ],
}

graph = subprocess.check_output(
    ["cargo", "tree", "--locked", "--target", "all", "--edges", "normal,build",
     "--prefix", "none", "--format", "{p}"], text=True
)
compiled = graph.splitlines()
for crate, advisories in UNCOMPILED_EXCEPTIONS.items():
    if any(line.startswith(f"{crate} v") for line in compiled):
        raise SystemExit(f"{crate} entered the compiled graph; remove it or resolve {', '.join(advisories)}")

ignored = [arg for advisories in UNCOMPILED_EXCEPTIONS.values() for advisory in advisories for arg in ("--ignore", advisory)]
subprocess.run(["cargo", "audit", "--deny", "unsound", *ignored], check=True)
