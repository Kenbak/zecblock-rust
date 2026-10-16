-- Default ACLs can give a newly created cache more than its SELECT/INSERT API.
-- Restrict only this table; leave its owner, source tables and defaults alone.
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '120s';

DO $$
DECLARE
    saved_grants jsonb;
    r record;
BEGIN
    -- Snapshot before CASCADE can remove grants delegated by another grantee.
    -- Read the actual ACL, including PUBLIC (OID 0) and inherited group roles.
    SELECT COALESCE(jsonb_agg(to_jsonb(grants)), '[]'::jsonb)
    INTO saved_grants
    FROM (
        SELECT acl.grantee,
               bool_or(acl.privilege_type = 'SELECT') AS can_select,
               bool_or(acl.privilege_type = 'INSERT') AS can_insert,
               bool_or(acl.privilege_type = 'SELECT' AND acl.is_grantable) AS select_grantable,
               bool_or(acl.privilege_type = 'INSERT' AND acl.is_grantable) AS insert_grantable
        FROM pg_class AS t
        CROSS JOIN LATERAL aclexplode(COALESCE(t.relacl, acldefault('r', t.relowner))) AS acl
        WHERE t.oid = 'public.block_subsidy_allocations'::regclass
          AND acl.grantee <> t.relowner
        GROUP BY acl.grantee
    ) AS grants;

    FOR r IN SELECT * FROM jsonb_to_recordset(saved_grants) AS grants(grantee oid)
    LOOP
        IF r.grantee = 0 THEN
            REVOKE ALL PRIVILEGES ON TABLE public.block_subsidy_allocations FROM PUBLIC CASCADE;
        ELSE
            -- ALL also removes version-specific rights such as PG17+ MAINTAIN.
            EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.block_subsidy_allocations FROM %I CASCADE',
                           pg_get_userbyid(r.grantee));
        END IF;
    END LOOP;

    FOR r IN SELECT * FROM jsonb_to_recordset(saved_grants) AS grants(
        grantee oid, can_select boolean, can_insert boolean,
        select_grantable boolean, insert_grantable boolean
    )
    LOOP
        -- Never restore PUBLIC access, including a default public writer grant.
        IF r.grantee <> 0 THEN
            IF r.can_select THEN
                EXECUTE format('GRANT SELECT ON TABLE public.block_subsidy_allocations TO %I%s',
                               pg_get_userbyid(r.grantee),
                               CASE WHEN r.select_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
            END IF;
            IF r.can_insert THEN
                EXECUTE format('GRANT INSERT ON TABLE public.block_subsidy_allocations TO %I%s',
                               pg_get_userbyid(r.grantee),
                               CASE WHEN r.insert_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
            END IF;
        END IF;
    END LOOP;
END $$;

COMMIT;
