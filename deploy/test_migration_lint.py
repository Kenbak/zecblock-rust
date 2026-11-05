import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("migration_lint", Path(__file__).with_name("lint-migration.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MigrationLintTests(unittest.TestCase):
    def test_concurrent_index_after_commit_is_allowed(self):
        self.assertEqual(module.lint("BEGIN; CREATE TABLE x (id int); COMMIT; CREATE INDEX CONCURRENTLY x_idx ON x(id);")[0], [])

    def test_concurrent_index_inside_transaction_is_rejected(self):
        for begin in ["BEGIN", "START TRANSACTION"]:
            with self.subTest(begin=begin):
                self.assertTrue(module.lint(f"{begin}; CREATE INDEX CONCURRENTLY x_idx ON x(id); COMMIT;")[0])

    def test_blocking_indexes_remain_rejected(self):
        for sql in ['CREATE INDEX x_idx ON x(id);', 'CREATE UNIQUE INDEX "CONCURRENTLY" ON x(id);']:
            self.assertTrue(module.lint(sql)[0])

    def test_index_on_table_created_in_same_transaction_is_allowed(self):
        for sql in [
            "BEGIN; CREATE TABLE IF NOT EXISTS x (id int); CREATE INDEX IF NOT EXISTS x_idx ON x(id); COMMIT;",
            "BEGIN; CREATE TABLE x (id int); CREATE UNIQUE INDEX x_idx ON ONLY x USING btree (id); COMMIT;",
            "BEGIN; CREATE TABLE public.x (id int); CREATE INDEX x_idx ON PUBLIC.X(id); COMMIT;",
        ]:
            with self.subTest(sql=sql):
                self.assertEqual(module.lint(sql)[0], [])

    def test_index_on_table_not_created_in_the_open_transaction_is_rejected(self):
        for sql in [
            "BEGIN; CREATE TABLE x (id int); CREATE INDEX y_idx ON y(id); COMMIT;",
            "BEGIN; CREATE TABLE x (id int); COMMIT; CREATE INDEX x_idx ON x(id);",
            "BEGIN; CREATE TABLE x (id int); COMMIT; BEGIN; CREATE INDEX x_idx ON x(id); COMMIT;",
            "CREATE TABLE x (id int); CREATE INDEX x_idx ON x(id);",
            "BEGIN; CREATE TABLE x (id int); ROLLBACK; BEGIN; CREATE INDEX x_idx ON x(id); COMMIT;",
            'BEGIN; CREATE TABLE "x" (id int); CREATE INDEX x_idx ON "x"(id); COMMIT;',
            "BEGIN; CREATE TABLE x AS SELECT 1 AS id; CREATE INDEX x_idx ON x(id); COMMIT;",
            "BEGIN; CREATE TABLE x (id int); CREATE INDEX x_idx ON public.x(id); COMMIT;",
        ]:
            with self.subTest(sql=sql):
                self.assertTrue(module.lint(sql)[0])

    def test_comments_and_quoted_function_bodies_are_not_transactions(self):
        sql = """-- BEGIN; CREATE INDEX x ON y(id);
        /* BEGIN; /* nested */ COMMIT; */
        CREATE FUNCTION f() RETURNS void AS $body$ BEGIN PERFORM 'COMMIT;'; END $body$ LANGUAGE plpgsql;
        SELECT 'BEGIN;', "BEGIN";
        CREATE INDEX CONCURRENTLY x_idx ON x(id);"""
        self.assertEqual(module.lint(sql)[0], [])

    def test_rollback_to_savepoint_keeps_transaction_open(self):
        self.assertTrue(module.lint("BEGIN; SAVEPOINT a; ROLLBACK TO a; CREATE INDEX CONCURRENTLY x_idx ON x(id);")[0])

    def test_commit_and_chain_keeps_transaction_open(self):
        self.assertTrue(module.lint("BEGIN; COMMIT AND CHAIN; CREATE INDEX CONCURRENTLY x_idx ON x(id);")[0])

    def test_unterminated_quotes_fail_closed(self):
        for sql in ["SELECT 'bad", "DO $tag$ bad", "/* bad"]:
            with self.assertRaises(ValueError):
                module.lint(sql)

    def test_default_warning_is_preserved(self):
        self.assertTrue(module.lint("ALTER TABLE x ADD COLUMN t timestamptz DEFAULT now();")[1])

    def test_all_managed_repository_migrations_pass(self):
        root = Path(__file__).resolve().parents[1]
        for path in sorted((root / 'schema/migrations').glob('*.sql')):
            if int(path.name.split('_')[0]) > 15:
                with self.subTest(path=path.name):
                    self.assertEqual(module.lint(path.read_text())[0], [])


if __name__ == '__main__':
    unittest.main()
