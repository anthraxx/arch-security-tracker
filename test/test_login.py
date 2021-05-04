from flask import url_for
from flask_login import current_user
from werkzeug.exceptions import Unauthorized

from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker.form.login import ERROR_ACCOUNT_DISABLED
from tracker.form.login import ERROR_INVALID_USERNAME_PASSWORD

from .conftest import DEFAULT_USERNAME
from .conftest import assert_logged_in
from .conftest import assert_not_logged_in
from .conftest import create_user
from .conftest import logged_in


def test_login_view(db, client):
    resp = client.get(url_for('tracker.login'))
    assert 200 == resp.status_code


@create_user
def test_login_success(db, client):
    resp = client.post(url_for('tracker.login'), follow_redirects=True,
                       data=dict(username=DEFAULT_USERNAME, password=DEFAULT_USERNAME))
    assert_logged_in(resp)
    assert DEFAULT_USERNAME == current_user.name


@create_user
def test_login_invalid_credentials(db, client):
    resp = client.post(url_for('tracker.login'), data={'username': DEFAULT_USERNAME,
                                               'password': 'N' * TRACKER_PASSWORD_LENGTH_MIN})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_INVALID_USERNAME_PASSWORD in resp.data.decode()


def test_login_invalid_form(db, client):
    resp = client.post(url_for('tracker.login'), data={'username': DEFAULT_USERNAME})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert 'This field is required.' in resp.data.decode()


@create_user(active=False)
def test_login_disabled(db, client):
    resp = client.post(url_for('tracker.login'), data={'username': DEFAULT_USERNAME, 'password': DEFAULT_USERNAME})
    assert_not_logged_in(resp, status_code=Unauthorized.code)
    assert ERROR_ACCOUNT_DISABLED in resp.data.decode()


@logged_in
def test_login_logged_in_redirect(db, client):
    resp = client.post(url_for('tracker.login'), follow_redirects=False)
    assert 302 == resp.status_code
    assert resp.location.endswith('/issues')


@logged_in
def test_logout(db, client):
    resp = client.post(url_for('tracker.logout'), follow_redirects=True)
    assert_not_logged_in(resp)


def test_logout_not_logged_in(db, client):
    resp = client.post(url_for('tracker.logout'), follow_redirects=False)
    assert 302 == resp.status_code
    assert resp.location.endswith('/issues')
