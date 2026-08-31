"""Password hashing and legacy migration tests."""

from argon2 import PasswordHasher


LEGACY_MD5_HASH = "482c811da5d5b4bc6d497ffa98491e38"


def test_new_password_uses_argon2id():
    from app.auth import hash_password

    stored_hash = hash_password("Password123!")

    assert stored_hash.startswith("$argon2id$")


def test_legacy_md5_password_is_migrated():
    from app.auth import authenticate_user

    result = authenticate_user(
        "password123",
        LEGACY_MD5_HASH,
    )

    assert isinstance(result, str)

    hasher = PasswordHasher()

    assert hasher.verify(
        result,
        "password123",
    )


def test_wrong_legacy_password_is_rejected():
    from app.auth import authenticate_user

    result = authenticate_user(
        "wrong-password",
        LEGACY_MD5_HASH,
    )

    assert result is False


def test_existing_argon2id_password_is_verified():
    from app.auth import (
        authenticate_user,
        hash_password,
    )

    stored_hash = hash_password(
        "Password123!",
    )

    result = authenticate_user(
        "Password123!",
        stored_hash,
    )

    assert result is True


def test_legacy_hash_is_not_returned_after_successful_migration():
    from app.auth import authenticate_user

    result = authenticate_user(
        "password123",
        LEGACY_MD5_HASH,
    )

    assert result != LEGACY_MD5_HASH
    assert result.startswith("$argon2id$")