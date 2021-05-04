from flask import url_for
from werkzeug.exceptions import NotFound

from .conftest import DEFAULT_GROUP_ID
from .conftest import DEFAULT_GROUP_NAME
from .conftest import create_group
from .conftest import create_package


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_vulnerable(db, client):
    resp = client.get(url_for('tracker.index_vulnerable'), follow_redirects=True)
    assert 200 == resp.status_code
    assert DEFAULT_GROUP_NAME in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_all(db, client):
    resp = client.get(url_for('tracker.index_all'), follow_redirects=True)
    assert 200 == resp.status_code
    assert DEFAULT_GROUP_NAME in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_json(db, client):
    resp = client.get(url_for('tracker.index_json', only_vulernable=False, path='all.json'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]['name'] == DEFAULT_GROUP_NAME


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_vulnerable_json(db, client):
    resp = client.get(url_for('tracker.index_vulnerable_json', path='vulnerable.json'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert len(data) == 1
    assert data[0]['name'] == DEFAULT_GROUP_NAME
