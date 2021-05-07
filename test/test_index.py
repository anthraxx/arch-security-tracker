from flask import url_for
from werkzeug.exceptions import NotFound

from tracker.model.enum import Remote
from tracker.model.enum import Severity

from .conftest import DEFAULT_GROUP_ID
from .conftest import DEFAULT_GROUP_NAME
from .conftest import create_group
from .conftest import create_issue
from .conftest import create_package


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_index(db, client):
    resp = client.get(url_for('tracker.index'), follow_redirects=True)
    assert 200 == resp.status_code
    assert DEFAULT_GROUP_NAME not in resp.data.decode()


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



@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3')
def test_index_pagination_404_on_wrong_index(db, client):
    resp = client.get(url_for('tracker.index', page=0xdead), follow_redirects=True)
    assert 404 == resp.status_code


@create_package(name='morty', version='1.3-7')
@create_group(issues=map(lambda i: f'CVE-0001-100{i}', range(1, 50)),
              packages=['morty'], fixed='1.3-8')
def test_index_pagination_exists(db, client):
    resp = client.get(url_for('tracker.index'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.data.decode()
    assert 'issue_top_pagination' in data
    assert 'issue_bottom_pagination' in data
    assert  url_for('tracker.index', page=2) in data


@create_package(name='morty', version='1.3-7')
@create_issue(id='CVE-0001-0001')
@create_issue(id='CVE-0002-000', count=2)
@create_issue(id='CVE-0003-000', count=3)
@create_issue(id='CVE-0004-000', count=4)
@create_issue(id='CVE-0005-000', count=5)
@create_issue(id='CVE-0001-100', count=6)
@create_issue(id='CVE-0002-100', count=7)
@create_issue(id='CVE-0003-100', count=8)
@create_issue(id='CVE-0004-100', count=9)
@create_issue(id='CVE-0005-100', count=10)
@create_group(issues=
              list(map(lambda i: f'CVE-0001-100{i}', range(1, 7))) +
              list(map(lambda i: f'CVE-0002-100{i}', range(1, 8))) +
              list(map(lambda i: f'CVE-0003-100{i}', range(1, 9))) +
              list(map(lambda i: f'CVE-0004-100{i}', range(1, 10))) +
              list(map(lambda i: f'CVE-0005-100{i}', range(1, 11))),
              packages=['morty'], fixed='1.3-8')
def test_index_pagination_pages_correctly(db, client):
    PAGE_1_CVES = [
        'CVE-0005-1009', 'CVE-0005-1008', 'CVE-0005-1007', 'CVE-0005-1006', 'CVE-0005-1005',
        'CVE-0003-1007', 'CVE-0003-1006', 'CVE-0003-1005', 'CVE-0003-1004', 'CVE-0003-1003']
    PAGE_2_CVES = [
        'CVE-0003-1002', 'CVE-0003-1001', 'CVE-0002-1007', 'CVE-0002-1006', 'CVE-0002-1005',
        'CVE-0001-1005', 'CVE-0001-1004', 'CVE-0001-1003', 'CVE-0001-1002', 'CVE-0001-1001']

    resp_1 = client.get(url_for('tracker.index', page=1), follow_redirects=True)
    resp_2 = client.get(url_for('tracker.index', page=2), follow_redirects=True)
    assert 200 == resp_1.status_code
    assert 200 == resp_2.status_code

    page_1 = resp_1.data.decode()
    page_2 = resp_2.data.decode()

    for cve_of_page_1 in PAGE_1_CVES:
        assert cve_of_page_1 in page_1
        assert cve_of_page_1 not in page_2

    for cve_of_page_2 in PAGE_2_CVES:
        assert cve_of_page_2 in page_2
        assert cve_of_page_2 not in page_1
