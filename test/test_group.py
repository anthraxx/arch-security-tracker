from werkzeug.exceptions import NotFound
from flask import url_for

from .conftest import logged_in, create_package, create_group, default_group_dict, DEFAULT_GROUP_ID, DEFAULT_GROUP_NAME, DEFAULT_ISSUE_ID, ERROR_LOGIN_REQUIRED
from app.model.enum import UserRole, Affected, Status
from app.model.cve import CVE
from app.model.cvegroup import CVEGroup
from app.view.add import ERROR_GROUP_WITH_ISSUE_EXISTS


def set_and_assert_group_data(db, client, route, pkgnames=['foo'], issues=['CVE-1234-1234', 'CVE-2222-2222'],
                              affected='1.2.3-4', fixed='1.2.3-5', status=Affected.affected, bug_ticket='1234',
                              reference='https://security.archlinux.org', notes='the cacke\nis\na\nlie',
                              advisory_qualified=False):
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        affected=affected,
        fixed=fixed,
        status=status.name,
        bug_ticket=bug_ticket,
        reference=reference,
        notes=notes,
        advisory_qualified='true' if advisory_qualified else None))

    resp = client.post(route, follow_redirects=True, data=data)
    assert 200 == resp.status_code

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert DEFAULT_GROUP_ID == group.id
    assert affected == group.affected
    assert fixed == group.fixed
    assert Status.vulnerable == group.status
    assert bug_ticket == group.bug_ticket
    assert reference == group.reference
    assert notes == group.notes
    assert advisory_qualified == group.advisory_qualified

    assert list(sorted(issues)) == list(sorted([issue.cve.id for issue in group.issues]))
    assert list(sorted(pkgnames)) == list(sorted([pkg.pkgname for pkg in group.packages]))


@create_package(name='foo')
@logged_in(role=UserRole.reporter)
def test_reporter_can_add(db, client):
    resp = client.post(url_for('add_group'), follow_redirects=True,
                       data=default_group_dict(dict(pkgnames='foo')))
    assert 200 == resp.status_code

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert DEFAULT_GROUP_ID == group.id


@create_package(name='foo')
@logged_in
def test_add_implicit_issue_creation(db, client):
    issue_id = 'CVE-4242-4242'
    resp = client.post(url_for('add_group'), follow_redirects=True,
                       data=default_group_dict(dict(pkgnames='foo', cve=issue_id)))
    assert 200 == resp.status_code

    cve = CVE.query.get(issue_id)
    assert issue_id == cve.id


@create_package(name='foo', version='1.2.3-4')
@logged_in
def test_add_group(db, client):
    set_and_assert_group_data(db, client, url_for('add_group'))


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_edit_group(db, client):
    set_and_assert_group_data(db, client, url_for('edit_group', avg=DEFAULT_GROUP_NAME))


def test_add_needs_login(db, client):
    resp = client.get(url_for('add_group'), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_group
def test_edit_needs_login(db, client):
    resp = client.get(url_for('edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@logged_in
def test_show_group_not_found(db, client):
    resp = client.get(url_for('show_group', avg='AVG-42'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@logged_in
def test_edit_group_not_found(db, client):
    resp = client.get(url_for('edit_group', avg='AVG-42'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_group_packge_dropped_from_repo(db, client):
    resp = client.get(url_for('show_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert 200 == resp.status_code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_warn_on_add_group_with_existing_issue(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222', DEFAULT_ISSUE_ID]
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames)))

    resp = client.post(url_for('add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_GROUP_WITH_ISSUE_EXISTS.format(DEFAULT_GROUP_ID, DEFAULT_ISSUE_ID, pkgnames[0]) in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_dont_warn_on_add_group_without_existing_issue(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222']
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames)))

    resp = client.post(url_for('add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_GROUP_WITH_ISSUE_EXISTS.format(DEFAULT_GROUP_ID, DEFAULT_ISSUE_ID, pkgnames[0]) not in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_warn_on_add_group_with_package_already_having_open_group(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222', DEFAULT_ISSUE_ID]
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames)))

    resp = client.post(url_for('add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_GROUP_WITH_ISSUE_EXISTS.format(DEFAULT_GROUP_ID, DEFAULT_ISSUE_ID, pkgnames[0]) in resp.data.decode()


@create_package(name='foo')
@logged_in
def test_add_group_with_dot_in_pkgrel(db, client):
    set_and_assert_group_data(db, client, url_for('add_group'), affected='1.2-3.4')


@create_package(name='foo')
@logged_in
def test_dont_add_group_with_dot_at_beginning_of_pkgrel(db, client):
    pkgnames = ['foo']
    issues = [DEFAULT_ISSUE_ID]
    affected = '1.3-.37'
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        affected=affected))

    resp = client.post(url_for('add_group'), follow_redirects=True, data=data)
    assert 'Invalid input.' in resp.data.decode()
