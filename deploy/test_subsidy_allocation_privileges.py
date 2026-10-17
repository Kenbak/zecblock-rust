"""Exercise cache ACL repair on a disposable native PostgreSQL database.

Set MIGRATION_TEST_DATABASE_URL to an administrator connection to run this
case. It creates and removes a unique database and roles, never altering the
connection's own database. CI supplies its disposable PostgreSQL service.
"""
import json
import os
from pathlib import Path
import subprocess
import unittest
from urllib.parse import urlsplit, urlunsplit
import uuid


@unittest.skipUnless(os.environ.get("MIGRATION_TEST_DATABASE_URL"),
                     "disposable PostgreSQL administrator connection required")
class SubsidyAllocationPrivilegeTests(unittest.TestCase):
    def setUp(self):
        self.admin_url = os.environ["MIGRATION_TEST_DATABASE_URL"]
        suffix = uuid.uuid4().hex
        self.database = "subsidy_acl_" + suffix
        self.roles = {name: "subsidy_" + name + "_" + suffix for name in (
            "writer", "reader", "group", "member", "delegate", "dangerous"
        )}
        parts = urlsplit(self.admin_url)
        if parts.scheme not in ("postgres", "postgresql"):
            self.fail("MIGRATION_TEST_DATABASE_URL must be a PostgreSQL URI")
        self.url = urlunsplit(parts._replace(path="/" + self.database))
        self.addCleanup(self.cleanup)
        for role in self.roles.values():
            self.sql(f'CREATE ROLE "{role}"', self.admin_url)
        self.sql(f'CREATE DATABASE "{self.database}"', self.admin_url)

    def sql(self, query, url=None):
        result = subprocess.run(
            ["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "--dbname", url or self.url],
            input=query, text=True, capture_output=True, timeout=30,
        )
        if result.returncode:
            self.fail(result.stderr)
        return result.stdout.strip()

    def cleanup(self):
        # The test never leaves a session open; FORCE also bounds cleanup if a
        # failed client left one behind. Roles have dependencies only here.
        self.sql(f'DROP DATABASE IF EXISTS "{self.database}" WITH (FORCE)', self.admin_url)
        for role in reversed(list(self.roles.values())):
            self.sql(f'DROP ROLE IF EXISTS "{role}"', self.admin_url)

    def migration(self, number):
        root = Path(__file__).resolve().parents[1]
        path, = (root / "schema/migrations").glob(number + "_*.sql")
        self.sql(path.read_text())

    def snapshot(self):
        return json.loads(self.sql("""
            SELECT json_build_object(
                'source_acl', (SELECT relacl::text FROM pg_class WHERE oid = 'public.blocks'::regclass),
                'other_acl', (SELECT relacl::text FROM pg_class WHERE oid = 'public.unrelated'::regclass),
                'default_acls', (SELECT json_agg(row_to_json(d) ORDER BY d.oid) FROM pg_default_acl d),
                'owner', (SELECT relowner FROM pg_class WHERE oid = 'public.block_subsidy_allocations'::regclass),
                'data', (SELECT json_agg(c) FROM public.block_subsidy_allocations c)
            )
        """))

    def test_default_all_and_inherited_grants_are_restricted_without_data_changes(self):
        r = self.roles
        self.sql(f"""
            CREATE TABLE public.blocks (height bigint);
            GRANT SELECT, INSERT ON public.blocks TO "{r['writer']}";
            GRANT SELECT ON public.blocks TO "{r['reader']}";
            GRANT "{r['group']}" TO "{r['member']}";
            ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES
                TO "{r['writer']}", "{r['group']}", PUBLIC;
            CREATE TABLE public.unrelated (value int);
        """)
        self.migration("036")
        self.sql(f"""
            GRANT SELECT, INSERT, UPDATE ON public.block_subsidy_allocations
                TO "{r['writer']}" WITH GRANT OPTION;
            SET ROLE "{r['writer']}";
            GRANT SELECT, INSERT, UPDATE ON public.block_subsidy_allocations TO "{r['delegate']}";
            RESET ROLE;
            GRANT DELETE, TRUNCATE, REFERENCES, TRIGGER ON public.block_subsidy_allocations
                TO "{r['dangerous']}";
            INSERT INTO public.block_subsidy_allocations
                (hash, height, chain, founders_zat, funding_streams_zat, miner_zat, source)
            VALUES (repeat('a', 64), 4465026, 'test', 0, 1, 2, 'getblocksubsidy');
        """)
        self.assertEqual(self.sql(f"SELECT has_table_privilege('{r['writer']}', 'public.block_subsidy_allocations', 'UPDATE')"), "t")
        before = self.snapshot()
        self.migration("037")
        self.assertEqual(self.snapshot(), before)
        after_acl = self.sql("SELECT relacl::text FROM pg_class WHERE oid = 'public.block_subsidy_allocations'::regclass")
        self.migration("037")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.sql("SELECT relacl::text FROM pg_class WHERE oid = 'public.block_subsidy_allocations'::regclass"), after_acl)

        # Check every privilege known to this PostgreSQL version. This includes
        # MAINTAIN on 17+, without spelling it in SQL accepted by older servers.
        privileges = self.sql("SELECT privilege_type FROM aclexplode(acldefault('r', current_user::regrole)) ORDER BY privilege_type").splitlines()
        expected = {"writer": {"SELECT", "INSERT"}, "reader": {"SELECT"},
                    "group": {"SELECT", "INSERT"}, "member": {"SELECT", "INSERT"},
                    "delegate": {"SELECT", "INSERT"}, "dangerous": set()}
        for name, allowed in expected.items():
            for privilege in privileges:
                with self.subTest(role=name, privilege=privilege):
                    actual = self.sql(f"SELECT has_table_privilege('{r[name]}', 'public.block_subsidy_allocations', '{privilege}')")
                    self.assertEqual(actual, "t" if privilege in allowed else "f")
        self.assertEqual(self.sql("SELECT count(*) FROM pg_class t CROSS JOIN LATERAL aclexplode(t.relacl) acl WHERE t.oid = 'public.block_subsidy_allocations'::regclass AND acl.grantee = 0"), "0")
        self.assertEqual(self.sql("SELECT bool_and(has_table_privilege(t.relowner, t.oid, acl.privilege_type)) FROM pg_class t CROSS JOIN LATERAL aclexplode(acldefault('r', t.relowner)) acl WHERE t.oid = 'public.block_subsidy_allocations'::regclass"), "t")
        self.sql(f"""
            SET ROLE "{r['writer']}";
            SELECT * FROM public.block_subsidy_allocations;
            INSERT INTO public.block_subsidy_allocations
                (hash, height, chain, founders_zat, funding_streams_zat, miner_zat, source)
            VALUES (repeat('b', 64), 4465027, 'test', 0, 1, 2, 'getblocksubsidy');
            RESET ROLE;
        """)


if __name__ == "__main__":
    unittest.main()
