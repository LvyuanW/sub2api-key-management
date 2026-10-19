#!/usr/bin/env python3
"""Narrow native API-key writer for sub2api v0.2.17; no wallet/user writes.

Environment: KEY_MANAGEMENT_PG_DSN; KEY_MANAGEMENT_REDIS_HOST/PORT/USERNAME/
PASSWORD/DB. Redis ACL: cache prefix apikey:auth:* and channel
auth:cache:invalidate, commands AUTH SELECT PING DEL PUBLISH only.
"""
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import inspect
import json
import os
import re
import sys
import unicodedata


KEY_COLUMNS = "id,user_id,key,name,group_id,status,quota,quota_used,expires_at,last_used_at,created_at"
INSERT_COLUMNS = ("user_id", "key", "name", "group_id", "status", "expires_at", "quota")
UPDATE_COLUMNS = ("name", "status", "expires_at", "updated_at")
IDENTITY_SQL = "SELECT id,email,notes,role,status FROM public.users WHERE id=%s AND deleted_at IS NULL"
KEYS_SQL = "SELECT " + KEY_COLUMNS + " FROM public.api_keys WHERE user_id=%s AND deleted_at IS NULL FOR UPDATE"
INSERT_SQL = """INSERT INTO public.api_keys
    (user_id,key,name,group_id,status,expires_at,quota)
    VALUES (%s,%s,%s,%s,'active',%s,0) RETURNING """ + KEY_COLUMNS
REQUIRED_SQL = """SELECT a.attname FROM pg_catalog.pg_attribute a
 LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE a.attrelid='public.api_keys'::regclass AND a.attnum>0
 AND NOT a.attisdropped AND a.attnotnull AND d.oid IS NULL
 AND a.attidentity='' AND a.attgenerated=''"""


class Conflict(Exception):
    pass


def integer(value, positive=True):
    if type(value) is not int or value > 9223372036854775807 or value < (1 if positive else 0):
        raise ValueError()
    return value


def name(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 100 or any(
            unicodedata.category(c) == "Cc" for c in value):
        raise ValueError()
    return value


def expiry(value):
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError()
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or not 1970 <= parsed.year <= 9999:
        raise ValueError()
    return parsed


def escaped_name(value):
    # Match Go html.EscapeString used by the native request sanitizer.
    return value.replace("&", "&amp;").replace("'", "&#39;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&#34;")


def validate_request(data):
    if not isinstance(data, dict) or set(data) - {"operation", "record", "credential", "fields"}:
        raise ValueError()
    operation = data.get("operation")
    if operation == "check":
        return operation, {}, "", {}
    if operation not in ("create", "update"):
        raise ValueError()
    record, credential, fields = data.get("record"), data.get("credential"), data.get("fields", {})
    if not isinstance(record, dict) or not isinstance(credential, str) or not re.fullmatch(r"sk-[0-9a-f]{64}", credential):
        raise ValueError()
    if not isinstance(record.get("nonce"), str) or not re.fullmatch(r"[0-9a-f]{32}", record["nonce"]):
        raise ValueError()
    for key in ("user_id", "admin_id"):
        integer(record.get(key))
    integer(record.get("key_id", 0), positive=False)
    if operation == "create":
        integer(record.get("group_id"))
        name(record.get("name"))
        expiry(record.get("expires_at"))
        if fields:
            raise ValueError()
    else:
        integer(record.get("key_id"))
        if not isinstance(fields, dict) or not fields or set(fields) - {"name", "status", "expires_at"}:
            raise ValueError()
        if "name" in fields:
            name(fields["name"])
        if "status" in fields and fields["status"] not in ("active", "inactive"):
            raise ValueError()
        if "expires_at" in fields:
            expiry(fields["expires_at"])
    return operation, record, credential, fields


def connect_db():
    import psycopg2
    from psycopg2.extras import RealDictCursor
    conn = psycopg2.connect(os.environ["KEY_MANAGEMENT_PG_DSN"], connect_timeout=3,
        application_name="key-management-key-writer",
        options="-c statement_timeout=4000 -c lock_timeout=2000")
    return conn, RealDictCursor


def connect_redis():
    import redis
    options = dict(host=os.getenv("KEY_MANAGEMENT_REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("KEY_MANAGEMENT_REDIS_PORT", "6379")),
        username=os.getenv("KEY_MANAGEMENT_REDIS_USERNAME", "key_management_keys"),
        password=os.environ["KEY_MANAGEMENT_REDIS_PASSWORD"],
        db=int(os.getenv("KEY_MANAGEMENT_REDIS_DB", "0")),
        socket_connect_timeout=2, socket_timeout=2, health_check_interval=0)
    if "lib_name" in inspect.signature(redis.Redis).parameters:
        options.update(lib_name=None, lib_version=None)
    return redis.Redis(**options)


def check(cur):
    # Only catalog reads and zero-row column permission checks; no application writes.
    cur.execute("SELECT id,email,notes,role,status,deleted_at FROM public.users LIMIT 0")
    cur.execute("SELECT " + KEY_COLUMNS + ",deleted_at FROM public.api_keys LIMIT 0")
    cur.execute(REQUIRED_SQL)
    if {row["attname"] for row in cur.fetchall()} - set(INSERT_COLUMNS):
        raise ValueError()
    for column in INSERT_COLUMNS:
        cur.execute("SELECT has_column_privilege(current_user,'public.api_keys',%s,'INSERT') AS allowed", (column,))
        if not cur.fetchone()["allowed"]:
            raise ValueError()
    for column in UPDATE_COLUMNS:
        cur.execute("SELECT has_column_privilege(current_user,'public.api_keys',%s,'UPDATE') AS allowed", (column,))
        if not cur.fetchone()["allowed"]:
            raise ValueError()
    cur.execute("SELECT has_sequence_privilege(current_user,pg_get_serial_sequence('public.api_keys','id'),'USAGE') AS allowed")
    if not cur.fetchone()["allowed"]:
        raise ValueError()
    # Native migration 184's SECURITY INVOKER update trigger inserts this one
    # SHA256 field. Check the trigger's required privileges before funding users.
    cur.execute("SELECT has_column_privilege(current_user,'public.auth_cache_invalidation_outbox','cache_key','INSERT') AS allowed")
    if not cur.fetchone()["allowed"]:
        raise ValueError()
    cur.execute("SELECT has_sequence_privilege(current_user,pg_get_serial_sequence('public.auth_cache_invalidation_outbox','id'),'USAGE') AS allowed")
    if not cur.fetchone()["allowed"]:
        raise ValueError()


def write(cur, operation, record, credential, fields):
    # A per-user transaction lock serializes helper create/update calls, including
    # the empty-table interval before the first unique key is inserted.
    lock_id = int.from_bytes(hashlib.sha256(("keymgr:" + str(record["user_id"])).encode()).digest()[:8], "big", signed=True)
    cur.execute("SELECT pg_advisory_xact_lock(%s)", (lock_id,))
    cur.execute(IDENTITY_SQL, (record["user_id"],))
    user = cur.fetchone()
    expected_email = "km-" + record["nonce"] + "@keymgr.invalid"
    expected_notes = "sub2api-key-management owner=" + str(record["admin_id"]) + " nonce=" + record["nonce"]
    if not user or user["id"] != record["user_id"] or user["email"] != expected_email or \
            user["notes"] != expected_notes or user["role"] != "user" or user["status"] != "active":
        raise Conflict()
    cur.execute(KEYS_SQL, (record["user_id"],))
    keys = cur.fetchall()
    if len(keys) > 1:
        raise Conflict()
    key = keys[0] if keys else None
    if key and (key["user_id"] != record["user_id"] or key["key"] != credential or
                (record.get("key_id", 0) and key["id"] != record["key_id"])):
        raise Conflict()
    if operation == "create":
        if key is None:
            if record.get("key_id", 0):
                raise Conflict()  # Never recreate a key that was deleted after creation.
            cur.execute(INSERT_SQL, (record["user_id"], credential, escaped_name(record["name"]),
                record["group_id"], expiry(record.get("expires_at"))))
            key = cur.fetchone()
        # Matching existing rows are not overwritten: retries preserve consumption,
        # expiry/status changes and all native defaults. Always invalidate cache.
        return dict(key)
    if key is None or key["id"] != record["key_id"]:
        raise Conflict()
    assignments, values = [], []
    for column in ("name", "status", "expires_at"):
        if column in fields:
            assignments.append(column + "=%s")  # column is from the fixed tuple above.
            value = expiry(fields[column]) if column == "expires_at" else fields[column]
            values.append(escaped_name(value) if column == "name" else value)
    values.extend((key["id"], record["user_id"], credential))
    cur.execute("UPDATE public.api_keys SET " + ",".join(assignments) + ",updated_at=NOW() "
        "WHERE id=%s AND user_id=%s AND key=%s AND deleted_at IS NULL", tuple(values))
    if cur.rowcount != 1:
        raise Conflict()
    return None


def invalidate(redis_client, credential):
    digest = hashlib.sha256(credential.encode()).hexdigest()
    # Same SHA key and Pub/Sub payload used by v0.2.17 APIKeyService.
    # Publish also evicts native negative L1 entries for newly created credentials.
    redis_client.delete("apikey:auth:" + digest)
    redis_client.publish("auth:cache:invalidate", digest)


def handle_request(data):
    operation, record, credential, fields = validate_request(data)
    conn, cursor_type = connect_db()
    try:
        conn.set_session(readonly=(operation == "check"))
        with conn.cursor(cursor_factory=cursor_type) as cur:
            if operation == "check":
                check(cur)
                redis_client = connect_redis()
                redis_client.ping()
                # Exercise the exact ACL commands before any user is funded.
                # This non-key sentinel is random, never an actual API credential.
                invalidate(redis_client, "key-management-preflight:" + os.urandom(32).hex())
                return {"ok": True}
            key = write(cur, operation, record, credential, fields)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    # A failed cache acknowledgement fails the operation after SQL commit. The
    # manager retries the same deterministic create or same field assignments.
    invalidate(connect_redis(), credential)
    return {"ok": True, "key": key} if operation == "create" else {"ok": True}


def json_value(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Decimal):
        return float(value)
    raise TypeError()


def main():
    try:
        raw = sys.stdin.buffer.read(16385)
        if not raw or len(raw) > 16384:
            raise ValueError()
        result = handle_request(json.loads(raw))
        sys.stdout.write(json.dumps(result, default=json_value, ensure_ascii=False))
        return 0
    except Conflict:
        sys.stdout.write('{"ok":false,"kind":"conflict"}')
    except Exception:
        # Never emit exception text, SQL, passwords, credentials or tracebacks.
        sys.stdout.write('{"ok":false,"kind":"unavailable"}')
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
