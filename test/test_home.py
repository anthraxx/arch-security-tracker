from flask import url_for
from werkzeug.exceptions import NotFound


def test_home(db, client):
    resp = client.get(url_for('tracker.home', path=''), follow_redirects=True)
    assert 200 == resp.status_code
