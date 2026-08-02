"""Versioned migrations: forward apply, idempotency, checksum + downgrade refusal."""

import sqlite3

import pytest

from aegis.api.migrations import Migration, MigrationError, run_migrations


def funcs(conn):
    return dict(
        execute_script=conn.executescript,
        execute=lambda sql, params=(): conn.execute(sql, params),
        query=lambda sql, params=(): conn.execute(sql, params).fetchall(),
        placeholder="?",
    )


def test_forward_apply_records_version():
    conn = sqlite3.connect(":memory:")
    run_migrations([Migration(1, "t1", "CREATE TABLE t1(a INTEGER);")], **funcs(conn))
    assert conn.execute("SELECT version, name FROM schema_migrations").fetchall() == [(1, "t1")]
    conn.execute("INSERT INTO t1(a) VALUES (1)")  # table exists


def test_reapply_is_idempotent():
    conn = sqlite3.connect(":memory:")
    m = [Migration(1, "t1", "CREATE TABLE t1(a INTEGER);")]
    run_migrations(m, **funcs(conn))
    run_migrations(m, **funcs(conn))  # no error, no duplicate
    assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 1


def test_checksum_mismatch_is_refused():
    conn = sqlite3.connect(":memory:")
    run_migrations([Migration(1, "t1", "CREATE TABLE t1(a INTEGER);")], **funcs(conn))
    with pytest.raises(MigrationError, match="checksum"):
        # same version, edited SQL -> different checksum
        run_migrations([Migration(1, "t1", "CREATE TABLE t1(a INTEGER, b INTEGER);")], **funcs(conn))


def test_downgrade_is_refused():
    conn = sqlite3.connect(":memory:")
    run_migrations(
        [Migration(1, "a", "CREATE TABLE t1(a INTEGER);"),
         Migration(2, "b", "CREATE TABLE t2(a INTEGER);")],
        **funcs(conn),
    )
    with pytest.raises(MigrationError, match="downgrade"):
        run_migrations([Migration(1, "a", "CREATE TABLE t1(a INTEGER);")], **funcs(conn))


def test_incremental_forward_application():
    conn = sqlite3.connect(":memory:")
    m1 = Migration(1, "a", "CREATE TABLE t1(a INTEGER);")
    run_migrations([m1], **funcs(conn))
    m2 = Migration(2, "b", "CREATE TABLE t2(a INTEGER);")
    assert run_migrations([m1, m2], **funcs(conn)) == 2
    versions = [r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
    assert versions == [1, 2]
    conn.execute("INSERT INTO t2(a) VALUES (1)")  # t2 now exists


def test_sqlite_repository_uses_migrations(tmp_path):
    from aegis.api.persistence import SqliteRepository

    repo = SqliteRepository(str(tmp_path / "m.db"))
    rows = dict(repo._conn.execute("SELECT version, name FROM schema_migrations").fetchall())
    assert rows[1] == "initial_schema" and rows[2] == "scan_model"
    applied_count = len(rows)
    repo.close()

    # reopen: idempotent, same migrations, no re-application
    repo2 = SqliteRepository(str(tmp_path / "m.db"))
    assert repo2._conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == applied_count
    repo2.close()
