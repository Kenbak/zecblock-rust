#!/usr/bin/env python3
"""Check top-level online DDL; ignore quoted SQL bodies and comments."""
import re
import sys
from pathlib import Path


def statements(sql):
    """Yield top-level SQL with comments and quoted contents masked.

    Dollar-quoted function/DO bodies are opaque: their BEGIN/END are not
    transaction boundaries. Nested block comments and escaped quotes are handled.
    This is an online-DDL guard, not a complete PostgreSQL parser.
    """
    out = []
    i = 0
    while i < len(sql):
        if sql.startswith("--", i):
            end = sql.find("\n", i)
            i = len(sql) if end < 0 else end + 1
            out.append(" ")
        elif sql.startswith("/*", i):
            depth = 1
            i += 2
            while i < len(sql) and depth:
                if sql.startswith("/*", i):
                    depth += 1
                    i += 2
                elif sql.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                raise ValueError("unterminated block comment")
            out.append(" ")
        elif sql[i] in "\"'":
            quote = sql[i]
            escaped = quote == "'" and i > 0 and sql[i - 1] in "eE" and (
                i < 2 or not (sql[i - 2].isalnum() or sql[i - 2] == "_")
            )
            i += 1
            while i < len(sql):
                if escaped and sql[i] == "\\":
                    i += 2
                elif sql[i] == quote:
                    if i + 1 < len(sql) and sql[i + 1] == quote:
                        i += 2
                    else:
                        i += 1
                        break
                else:
                    i += 1
            else:
                raise ValueError("unterminated quoted value")
            out.append(" quoted ")
        elif sql[i] == "$" and (match := re.match(r"\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$", sql[i:])):
            tag = match.group()
            end = sql.find(tag, i + len(tag))
            if end < 0:
                raise ValueError("unterminated dollar quote")
            i = end + len(tag)
            out.append(" quoted ")
        elif sql[i] == ";":
            yield " ".join("".join(out).split())
            out = []
            i += 1
        else:
            out.append(sql[i])
            i += 1
    if "".join(out).strip():
        yield " ".join("".join(out).split())


IDENTIFIER = r"[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)?"
CREATE_TABLE = re.compile(
    rf"^CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({IDENTIFIER})\s*\(", re.I)
INDEX_TARGET = re.compile(rf"\bON\s+(?:ONLY\s+)?({IDENTIFIER})\s*(?:USING\s+\w+\s*)?\(", re.I)


def lint(sql):
    errors, warnings = [], []
    transaction = False
    # Tables created by this file inside the currently open transaction. A
    # plain CREATE INDEX on such a table locks only a table no other session
    # can see yet, so it cannot block online traffic. Quoted identifiers are
    # masked by statements() and therefore never qualify (fail closed).
    new_tables = set()
    for statement in statements(sql):
        if re.match(r"^(?:BEGIN|START TRANSACTION)\b", statement, re.I):
            transaction = True
            new_tables = set()
        elif re.match(r"^(?:COMMIT|END|ROLLBACK|ABORT)\b", statement, re.I):
            if not re.match(r"^ROLLBACK(?: WORK| TRANSACTION)? TO\b", statement, re.I):
                transaction = bool(re.search(r"\bAND CHAIN\b", statement, re.I))
                new_tables = set()
        create_table = CREATE_TABLE.match(statement)
        # statements() masks quoted text as the bare word "quoted"; never trust it.
        if create_table and transaction and "quoted" not in create_table[1].lower().split("."):
            new_tables.add(create_table[1].lower())
        create_index = re.match(r"^CREATE\s+(?:UNIQUE\s+)?INDEX\b(.*)", statement, re.I)
        if create_index:
            concurrent = re.match(r"^\s+CONCURRENTLY\b", create_index[1], re.I)
            target = INDEX_TARGET.search(create_index[1])
            if not concurrent and transaction and target and target[1].lower() in new_tables:
                pass
            elif not concurrent:
                errors.append("blocking CREATE INDEX (missing CONCURRENTLY)")
            elif transaction:
                errors.append("CONCURRENTLY cannot run inside a transaction block")
        if re.search(r"ADD\s+COLUMN\b.*DEFAULT\s+(?:now\s*\(|current_(?:date|time|timestamp)\b|random\s*\(|gen_random_uuid\s*\(|uuid_generate_v\d\s*\()", statement, re.I):
            warnings.append("ADD COLUMN with a volatile or time-dependent DEFAULT detected")
    return errors, warnings


def main():
    path = Path(sys.argv[1])
    version = re.match(r"^(\d+)", path.name)
    # Preserve the runner's immutable historical baseline exemption.
    if version and int(version[1]) <= 15:
        return 0
    try:
        errors, warnings = lint(path.read_text())
    except ValueError as error:
        errors, warnings = [str(error)], []
    for message in errors:
        print(f"ERROR: {path.name}: {message}", file=sys.stderr)
    for message in warnings:
        print(f"WARNING: {path.name}: {message}", file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    sys.exit(main())
