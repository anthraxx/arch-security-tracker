from flask import url_for
from werkzeug.exceptions import Forbidden
from werkzeug.exceptions import NotFound

from config import TRACKER_BUGTRACKER_URL
from tracker.model.cve import CVE
from tracker.model.cve import issue_types
from tracker.model.cvegroup import CVEGroup
from tracker.model.enum import Affected
from tracker.model.enum import Status
from tracker.model.enum import UserRole
from tracker.model.enum import affected_to_status
from tracker.view.add import ERROR_GROUP_WITH_ISSUE_EXISTS
from tracker.view.show import get_bug_project

from .conftest import DEFAULT_ADVISORY_ID
from .conftest import DEFAULT_GROUP_ID
from .conftest import DEFAULT_GROUP_NAME
from .conftest import DEFAULT_ISSUE_ID
from .conftest import ERROR_LOGIN_REQUIRED
from .conftest import create_advisory
from .conftest import create_group
from .conftest import create_package
from .conftest import default_group_dict
from .conftest import logged_in
from .util import AssertionHTMLParser


def set_and_assert_group_data(db, client, route, pkgnames=['foo'], issues=['CVE-1234-1234', 'CVE-2222-2222'],
                              affected='1.2.3-4', fixed='1.2.3-5', status=Affected.affected, bug_ticket='1234',
                              reference='https://security.archlinux.org', notes='the cacke\nis\na\nlie',
                              advisory_qualified=False, database='core'):
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

    if bug_ticket:
        assert TRACKER_BUGTRACKER_URL.format(bug_ticket) in resp.data.decode('utf-8')
    else:
        # Assert project and product category
        project = get_bug_project([database])
        assert 'project={}&amp;product_category=13'.format(project) in resp.data.decode('utf-8')


@create_package(name='foo')
@logged_in(role=UserRole.reporter)
def test_reporter_can_add(db, client):
    resp = client.post(url_for('tracker.add_group'), follow_redirects=True,
                       data=default_group_dict(dict(pkgnames='foo')))
    assert 200 == resp.status_code

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert DEFAULT_GROUP_ID == group.id


@create_package(name='foo')
@create_group(packages=['foo'])
@logged_in(role=UserRole.reporter)
def test_reporter_can_copy(db, client):
    resp = client.get(url_for('tracker.copy_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert 200 == resp.status_code
    assert ERROR_LOGIN_REQUIRED not in resp.data.decode()


@create_package(name='foo')
@logged_in
def test_add_implicit_issue_creation(db, client):
    issue_id = 'CVE-4242-4242'
    resp = client.post(url_for('tracker.add_group'), follow_redirects=True,
                       data=default_group_dict(dict(pkgnames='foo', cve=issue_id)))
    assert 200 == resp.status_code

    cve = CVE.query.get(issue_id)
    assert issue_id == cve.id


@create_package(name='foo', version='1.2.3-4')
@logged_in
def test_add_group(db, client):
    set_and_assert_group_data(db, client, url_for('tracker.add_group'))


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_edit_group(db, client):
    set_and_assert_group_data(db, client, url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME))


@create_package(name='foo', version='1.2.3-4')
@logged_in
def test_edit_group_bug_url_core(db, client):
    set_and_assert_group_data(db, client, url_for('tracker.add_group'), bug_ticket='')


@create_package(name='foo', version='1.2.3-4', database='community')
@logged_in
def test_edit_group_bug_url_community(db, client):
    set_and_assert_group_data(db, client, url_for('tracker.add_group'), bug_ticket='', database='community')


def test_add_needs_login(db, client):
    resp = client.get(url_for('tracker.add_group'), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_group
def test_edit_needs_login(db, client):
    resp = client.get(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@create_group
def test_copy_needs_login(db, client):
    resp = client.get(url_for('tracker.copy_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@logged_in
def test_show_group_not_found(db, client):
    resp = client.get(url_for('tracker.show_group', avg='AVG-42'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@logged_in
def test_edit_group_not_found(db, client):
    resp = client.get(url_for('tracker.edit_group', avg='AVG-42'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4',
              issues=['CVE-1111-1234', 'CVE-1234-12345', 'CVE-1111-12345',
                      'CVE-1234-11112', 'CVE-1234-111111', 'CVE-1234-11111'])
@logged_in
def test_edit_sort_cve_entries(db, client):
    resp = client.get(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert 200 == resp.status_code
    html = AssertionHTMLParser()
    html.feed(resp.data.decode())
    assert ['CVE-1111-1234',
            'CVE-1111-12345',
            'CVE-1234-11111',
            'CVE-1234-11112',
            'CVE-1234-12345',
            'CVE-1234-111111'] == html.get_element_by_id('cve').data.split()


@logged_in
def test_copy_group_not_found(db, client):
    resp = client.get(url_for('tracker.copy_group', avg='AVG-42'), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in
def test_group_packge_dropped_from_repo(db, client):
    resp = client.get(url_for('tracker.show_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
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

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
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

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
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

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert ERROR_GROUP_WITH_ISSUE_EXISTS.format(DEFAULT_GROUP_ID, DEFAULT_ISSUE_ID, pkgnames[0]) in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'], affected='1.0-1')
@logged_in
def test_add_group_fixed_version_older_then_affected(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222']
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        fixed='0.8-1'))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert 'Version must be newer.' in resp.data.decode()


@create_package(name='foo')
@logged_in
def test_add_group_with_dot_in_pkgrel(db, client):
    set_and_assert_group_data(db, client, url_for('tracker.add_group'), affected='1.2-3.4')


@create_package(name='foo', version='1.2.3-4')
@create_package(name='lib32-foo', version='1.2.3-4')
@logged_in
def test_add_group_missing_foo(db, client):
    pkgnames = ['lib32-foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222']
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        ))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert 'Missing AVG for foo' in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_package(name='lib32-foo', version='1.2.3-4')
@logged_in
def test_add_group_missing_lib32(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222']
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        ))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert 'Missing AVG for lib32-foo' in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_package(name='lib32-foo', version='1.2.3-4')
@logged_in
def test_add_group_missing_lib32_included(db, client):
    pkgnames = ['foo', 'lib32-foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222']
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        ))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert 'Missing AVG for lib32-foo' not in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@logged_in
def test_add_group_missing_lib32_invalid(db, client):
    pkgnames = ['foo']
    issues = ['CVE-1234-1234', 'CVE-2222-2222']
    data = default_group_dict(dict(
        cve='\n'.join(issues),
        pkgnames='\n'.join(pkgnames),
        ))

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert 'Missing AVG for lib32-foo' not in resp.data.decode()


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

    resp = client.post(url_for('tracker.add_group'), follow_redirects=True, data=data)
    assert 'Invalid input.' in resp.data.decode()


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in(role=UserRole.reporter)
def test_reporter_can_delete(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True,
                       data=dict(confirm=True))
    assert 200 == resp.status_code
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert avg is None


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
@logged_in(role=UserRole.reporter)
def test_abort_delete(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True,
                       data=dict(abort=True))
    assert 200 == resp.status_code
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert DEFAULT_GROUP_ID == avg.id


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foo'])
def test_delete_needs_login(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert ERROR_LOGIN_REQUIRED in resp.data.decode()


@logged_in
def test_delete_issue_not_found(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert resp.status_code == NotFound.code


@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
@logged_in
def test_forbid_delete_with_advisory(db, client):
    resp = client.post(url_for('tracker.delete_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert Forbidden.code == resp.status_code

@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4',
              issues=['CVE-1111-1234', 'CVE-1234-12345', 'CVE-1111-12345',
                      'CVE-1234-11112', 'CVE-1234-111111', 'CVE-1234-11111'])
@logged_in
def test_show_group_sort_cve_entries(db, client):
    resp = client.get(url_for('tracker.show_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True)
    assert 200 == resp.status_code
    html = AssertionHTMLParser()
    html.feed(resp.data.decode())
    cves = []
    for e in html.get_elements_by_tag('a'):
        if len(e.attrs) == 1 and e.attrs[0][0] == 'href':
            if e.data.startswith("CVE") and e.attrs[0][1].startswith("/CVE"):
                cves.append(e.data.strip())
    assert ['CVE-1234-111111',
            'CVE-1234-12345',
            'CVE-1234-11112',
            'CVE-1234-11111',
            'CVE-1111-12345',
            'CVE-1111-1234'] == cves

@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
@create_advisory(id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=issue_types[1])
def test_show_group_json(db, client):
    resp = client.get(url_for('tracker.show_group_json', avg=DEFAULT_GROUP_NAME, postfix='/json'), follow_redirects=True)
    assert 200 == resp.status_code
    data = resp.get_json()
    assert data['name'] == DEFAULT_GROUP_NAME
    assert data['issues'] == [DEFAULT_ISSUE_ID]
    assert data['packages'] == ['foo']
    assert data['affected'] == '1.2.3-3'
    assert data['fixed'] == '1.2.3-4'

def test_show_group_json_not_found(db, client):
    resp = client.get(url_for('tracker.show_group_json', avg=DEFAULT_GROUP_NAME, postfix='/json'), follow_redirects=True)
    assert NotFound.code == resp.status_code

@create_package(name='foo', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_fixed(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.fixed

@create_package(name='foo', version='1.2.3-3')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_vulnerable(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.vulnerable

@create_package(name='foo', version='1.2.3-3', database='testing')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_vulnerable_testing(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.vulnerable

@create_package(name='foo', version='1.2.3-3')
@create_package(name='foo', version='1.2.3-4', database='testing')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_testing(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.testing

@create_package(name='foo', version='1.2.3-4', database='testing')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_testing_only(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.testing

@create_package(name='foo', version='1.2.3-3', database='community')
@create_package(name='foo', version='1.2.3-4', database='community-testing')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_community_testing(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.testing

@create_package(name='foo', version='1.2.3-3')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_unknown(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.unknown, 'foo', avg.fixed)
    assert status == Status.unknown

@create_package(name='foo', version='1.2.3-3')
@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_not_affected(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.not_affected, 'foo', avg.fixed)
    assert status == Status.not_affected

@create_group(id=DEFAULT_GROUP_ID, packages=['foo'], affected='1.2.3-3', fixed='1.2.3-4')
def test_affected_to_status_unknown_package(db, client):
    avg = CVEGroup.query.get(DEFAULT_GROUP_ID)
    status = affected_to_status(Affected.affected, 'foo', avg.fixed)
    assert status == Status.unknown


@create_package(name='foopkg', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foopkg'])
@logged_in
def test_edit_group_non_relational_field_updates_changed_date(db, client):
    group_changed_old = CVEGroup.query.get(DEFAULT_GROUP_ID).changed

    data = default_group_dict(dict(notes='regular field change'))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_GROUP_NAME}' in resp.data.decode()

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert group.changed > group_changed_old


@create_package(name='foopkg', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foopkg'])
@logged_in
def test_edit_group_relational_field_issues_updates_changed_date(db, client):
    group_changed_old = CVEGroup.query.get(DEFAULT_GROUP_ID).changed

    data = default_group_dict(dict(cve=' '.join(['CVE-1234-1111', 'CVE-1234-2222'])))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_GROUP_NAME}' in resp.data.decode()

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert group.changed > group_changed_old


@create_package(name='foopkg', version='1.2.3-4', base='foo')
@create_package(name='foopkg2', version='1.2.3-4', base='foo')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foopkg'])
@logged_in
def test_edit_group_relational_field_packages_updates_changed_date(db, client):
    group_changed_old = CVEGroup.query.get(DEFAULT_GROUP_ID).changed

    data = default_group_dict(dict(pkgnames=' '.join(['foopkg', 'foopkg2'])))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_GROUP_NAME}' in resp.data.decode()

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert group.changed > group_changed_old


@create_package(name='foopkg', version='1.2.3-4')
@create_group(id=DEFAULT_GROUP_ID, issues=[DEFAULT_ISSUE_ID], packages=['foopkg'])
@logged_in
def test_edit_group_does_nothing_when_data_is_same(db, client):
    group_old = CVEGroup.query.get(DEFAULT_GROUP_ID)
    group_changed_old = group_old.changed

    data = default_group_dict(dict(status=Affected.affected.name))
    resp = client.post(url_for('tracker.edit_group', avg=DEFAULT_GROUP_NAME), follow_redirects=True, data=data)
    assert 200 == resp.status_code
    assert f'Edited {DEFAULT_GROUP_NAME}' not in resp.data.decode()

    group = CVEGroup.query.get(DEFAULT_GROUP_ID)
    assert group.changed == group_changed_old
