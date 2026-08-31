"""Legacy-password migration regression tests."""

from argon2 import PasswordHasher


def test_md5_password_is_migrated_to_argon2():
    from app.auth import authenticate_user

    legacy_md5 = "482c811da5d5b4bc6d497ffa98491e38"

    result = authenticate_user(
        "password123",
        legacy_md5,
    )

    assert isinstance(result, str)

    hasher = PasswordHasher()

    assert hasher.verify(
        result,
        "password123",
    )

    assert result.startswith("$argon2")


def test_wrong_password_does_not_migrate_md5():
    from app.auth import authenticate_user

    legacy_md5 = "482c811da5d5b4bc6d497ffa98491e38"

    result = authenticate_user(
        "definitely-wrong-password",
        legacy_md5,
    )

    assert result is False


def test_current_argon2_hash_is_accepted():
    from app.auth import authenticate_user

    hasher = PasswordHasher()
    stored_hash = hasher.hash("Password123!")

    result = authenticate_user(
        "Password123!",
        stored_hash,
    )

    assert result is True