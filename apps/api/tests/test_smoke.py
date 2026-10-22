def test_health(make_api):
    api = make_api()
    assert api.http.get("/health").json() == {"status": "ok"}
    assert api.http.get("/health/ready").status_code == 200
