def test_health_endpoint(
    client,
) -> None:
    response = client.get(
        "/health"
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
    }


def test_readiness_endpoint(
    client,
) -> None:
    response = client.get(
        "/ready"
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
    }
