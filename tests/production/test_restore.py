import pytest

from aegis.production.backup import BackupError
from aegis.production.restore import _database_dsn, validate_verification_database


def test_verification_database_name_is_strictly_bounded():
    assert validate_verification_database("aegis_verify_restore_1") == "aegis_verify_restore_1"
    for unsafe in ("aegis", "postgres", "aegis_verify_", "aegis_verify_BAD", "aegis_verify_x;DROP DATABASE aegis"):
        with pytest.raises(BackupError):
            validate_verification_database(unsafe)


def test_database_dsn_preserves_tls_and_credentials():
    source = "postgresql://svc:pw@pg.prod.internal:5432/aegis?sslmode=verify-full"
    assert _database_dsn(source, "aegis_verify_test") == (
        "postgresql://svc:pw@pg.prod.internal:5432/aegis_verify_test?sslmode=verify-full"
    )
