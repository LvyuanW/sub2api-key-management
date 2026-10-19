-- Connect to sub2api as a PostgreSQL superuser.
-- Create a NEW independent login before applying this file:
-- CREATE ROLE key_management_keys LOGIN PASSWORD '<random secret>';
-- No sub2api tables, indexes, columns or functions are created or changed.

ALTER ROLE key_management_keys SET statement_timeout = '4s';
ALTER ROLE key_management_keys SET lock_timeout = '2s';
ALTER ROLE key_management_keys SET search_path = pg_catalog, public;
ALTER ROLE key_management_keys SET log_parameter_max_length_on_error = 0;
ALTER ROLE key_management_keys SET log_min_error_statement = 'panic';
ALTER ROLE key_management_keys SET log_statement = 'none';
ALTER ROLE key_management_keys SET log_min_duration_statement = -1;
ALTER ROLE key_management_keys SET log_min_duration_sample = -1;
ALTER ROLE key_management_keys SET log_duration = off;

GRANT CONNECT ON DATABASE sub2api TO key_management_keys;
GRANT USAGE ON SCHEMA public TO key_management_keys;
GRANT SELECT (id, email, notes, role, status, deleted_at)
    ON public.users TO key_management_keys;
GRANT SELECT (id, user_id, key, name, group_id, status, quota, quota_used,
              expires_at, last_used_at, created_at, deleted_at)
    ON public.api_keys TO key_management_keys;
GRANT INSERT (user_id, key, name, group_id, status, expires_at, quota)
    ON public.api_keys TO key_management_keys;
GRANT UPDATE (name, status, expires_at, updated_at)
    ON public.api_keys TO key_management_keys;
GRANT USAGE ON SEQUENCE public.api_keys_id_seq TO key_management_keys;

-- Native migration 184's existing AFTER UPDATE trigger enqueues status/expiry
-- cache invalidations with the caller's permissions. Only its SHA256 column and
-- sequence are needed; no direct reads/updates/deletes of the outbox are granted.
GRANT INSERT (cache_key) ON public.auth_cache_invalidation_outbox TO key_management_keys;
GRANT USAGE ON SEQUENCE public.auth_cache_invalidation_outbox_id_seq TO key_management_keys;

-- Redis administrator provisioning (persist in the configured ACL file):
-- ACL SETUSER key_management_keys reset on >RANDOM_SECRET
--   ~apikey:auth:* &auth:cache:invalidate +auth +select +ping +del +publish
-- No GET, SET, SCAN, database data deletion, or other channel access is granted.
-- The helper DEL targets only apikey:auth:<SHA256(credential)> and publishes
-- that SHA256 digest (without prefix) to the native invalidation channel.
-- Preflight also PINGs and probes DEL/PUBLISH with a fresh random sentinel digest
-- in this cache namespace; it never targets an actual managed API credential.
