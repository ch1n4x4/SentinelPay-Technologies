"""Login and OTP rate-limit regression tests."""


def test_login_is_rate_limited_by_ip(
    client,
):
    statuses = []

    for _ in range(7):
        response = client.post(
            "/v1/auth/login",
            json={
                "email": "user@example.com",
                "password": "wrong-password",
            },
        )

        statuses.append(response.status_code)

    assert 429 in statuses


def test_login_is_rate_limited_by_account_across_ips(
    client_factory,
):
    statuses = []

    for index in range(1, 7):
        client = client_factory(
            remote_addr=f"10.0.0.{index}",
        )

        response = client.post(
            "/v1/auth/login",
            json={
                "email": "same-account@example.com",
                "password": "wrong-password",
            },
        )

        statuses.append(response.status_code)

    assert 429 in statuses


def test_otp_is_rate_limited_by_ip(
    client,
):
    statuses = []

    for _ in range(7):
        response = client.post(
            "/v1/auth/otp",
            json={
                "phone": "+2348000000000",
            },
        )

        statuses.append(response.status_code)

    assert 429 in statuses


def test_otp_is_rate_limited_by_phone_across_ips(
    client_factory,
):
    statuses = []

    for index in range(1, 7):
        client = client_factory(
            remote_addr=f"10.0.1.{index}",
        )

        response = client.post(
            "/v1/auth/otp",
            json={
                "phone": "+2348000000000",
            },
        )

        statuses.append(response.status_code)

    assert 429 in statuses


def test_email_bucket_is_case_and_whitespace_normalized(
    client_factory,
):
    variants = [
        "SameUser@example.com",
        "sameuser@example.com ",
        " SAMEUSER@EXAMPLE.COM",
        "sameuser@example.com",
        "SaMeUsEr@example.com",
        "sameuser@example.com",
    ]

    statuses = []

    for index, email in enumerate(variants):
        client = client_factory(
            remote_addr=f"10.0.2.{index + 1}",
        )

        response = client.post(
            "/v1/auth/login",
            json={
                "email": email,
                "password": "wrong-password",
            },
        )

        statuses.append(response.status_code)

    assert 429 in statuses