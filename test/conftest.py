from datetime import datetime
from functools import wraps
from re import match
from urllib.parse import urlparse

import pytest
from flask import url_for
from flask_login import current_user

from tracker import advisory
from tracker import create_app
from tracker import db as flask_db
from tracker.advisory import advisory_get_label
from tracker.model.advisory import Advisory
from tracker.model.advisory import advisory_regex
from tracker.model.cve import CVE
from tracker.model.cve import issue_types
from tracker.model.cvegroup import CVEGroup
from tracker.model.cvegroupentry import CVEGroupEntry
from tracker.model.cvegrouppackage import CVEGroupPackage
from tracker.model.enum import Affected
from tracker.model.enum import Publication
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import UserRole
from tracker.model.enum import affected_to_status
from tracker.model.enum import highest_severity
from tracker.model.package import Package
from tracker.model.user import User
from tracker.user import hash_password
from tracker.user import random_string

DEFAULT_ADVISORY_ID = advisory_get_label()
DEFAULT_USERNAME = 'cyberwehr12345678'
ERROR_LOGIN_REQUIRED = 'Please log in to access this page.'
ERROR_INVALID_CHOICE = 'Not a valid choice'


@pytest.fixture(scope="session")
def app(request):
    flask_app = create_app()
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    flask_app.config['SERVER_NAME'] = 'cyber.local'
    with flask_app.app_context():
        yield flask_app


@pytest.fixture(scope="session")
def client(app):
    return app.test_client()


@pytest.fixture(scope="session")
def db(app, request):
    with app.app_context():
        yield flask_db
        flask_db.drop_all()


@pytest.fixture(autouse=True, scope='function')
def run_scoped(app, db, client, request):
    with app.app_context():
        connection = db.engine.connect()
        transaction = connection.begin()

        options = dict(bind=connection, binds={})
        session = db.create_scoped_session(options=options)

        db.session = session
        db.create_all()

        with client:
            yield

        db.drop_all()
        transaction.rollback()
        connection.close()
        session.remove()


@pytest.fixture(scope='function')
def patch_get(monkeypatch, request):
    status_code = 200
    text = ''
    if hasattr(request, 'param'):
        if isinstance(request.param, str):
            text = request.param
        else:
            status_code = request.param

    def mocked_get(uri, *args, **kwargs):
        nonlocal text, status_code
        uri = urlparse(uri)
        path = uri.path
        if uri.path.startswith('/'):
            path = uri.path[1:]
        if match(advisory_regex, path):
            text = '<PRE>{}\n-------------- next part --------------</PRE>'.format(create_advisory_content(id=path))
        return type('MockedReq', (), {'status_code': status_code, 'text': text})()
    monkeypatch.setattr(advisory, 'get', mocked_get)


def assert_logged_in(response, status_code=200):
    assert status_code == response.status_code
    assert b'logout' in response.data
    assert b'login' not in response.data
    assert current_user.is_authenticated


def assert_not_logged_in(response, status_code=200):
    assert status_code == response.status_code
    assert b'logout' not in response.data
    assert b'login' in response.data
    assert not current_user.is_authenticated


def logged_in(func=None, role=UserRole.administrator, username=DEFAULT_USERNAME, password=None):
    def decorator(func):
        @create_user(role=role, username=username, password=password)
        @wraps(func)
        def wrapper(db, client, *args, **kwargs):
            resp = client.post(url_for('tracker.login'), follow_redirects=True,
                               data=dict(username=username, password=password if password else username))
            assert_logged_in(resp)
            func(db=db, client=client, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


def create_user(func=None, username=DEFAULT_USERNAME, password=None, role=UserRole.reporter,
                email=None, salt=None, active=True, idp_id=None):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            user = User()
            user.active = active
            user.name = username
            user.password = password if password else username
            user.role = role
            user.email = email if email else '{}@cyber.cyber'.format(username)
            user.salt = salt if salt else random_string()
            user.password = hash_password(user.password, user.salt)
            user.idp_id = idp_id

            db.session.add(user)
            db.session.commit()
            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


DEFAULT_ISSUE_ID = 'CVE-2016-1337'


def default_issue_dict(overrides=dict()):
    data = dict(cve=DEFAULT_ISSUE_ID, issue_type=issue_types[0], remote=Remote.unknown.name,
                severity=Severity.unknown.name, description='', notes='', reference='')
    data.update(overrides)
    return data


def create_issue(func=None, id=DEFAULT_ISSUE_ID, issue_type=issue_types[0], remote=Remote.unknown,
                 severity=Severity.unknown, description='', notes='', reference='', count=1):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            for num in range(1, count + 1):
                issue = CVE()
                issue.id = id if count <= 1 else '{}{}'.format(id, num)
                issue.issue_type = issue_type
                issue.remote = remote
                issue.severity = severity
                issue.description = description
                issue.notes = notes
                issue.reference = reference
                db.session.add(issue)
            db.session.commit()
            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


def create_package(func=None, id=None, name=None, base=None, version='1.0-1', arch='any',
                   database='core', description='', url=None, filename='somefile-1.0-1-any.tar.xz',
                   md5sum='md5', sha256sum='sha256', builddate=0):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            package = Package()
            if id:
                package.id = id
            package.name = name
            package.base = base if base else name
            package.version = version
            package.arch = arch
            package.database = database
            package.description = description
            package.url = url
            package.filename = filename
            package.md5sum = md5sum
            package.sha256sum = sha256sum
            package.builddate = builddate

            db.session.add(package)
            db.session.commit()
            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


DEFAULT_GROUP_ID = 1
DEFAULT_GROUP_NAME = 'AVG-{}'.format(DEFAULT_GROUP_ID)


def default_group_dict(overrides=dict()):
    data = dict(cve=DEFAULT_ISSUE_ID, pkgnames='foopkg', affected='1.0-1', fixed=None,
                status=Affected.unknown.name, bug_ticket='', reference='', notes='',
                advisory_qualified=True)
    data.update(overrides)
    return data


def create_group(func=None, id=None, status=None, severity=None,
                 affected='1.0-1', fixed=None, bug_ticket='', reference='', notes='',
                 created=datetime.utcnow(), advisory_qualified=True, issues=[DEFAULT_ISSUE_ID], packages=['foo'], count=1):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            issue_objs = []
            for issue in issues:
                issue_objs.append(db.get_or_create(CVE, id=issue))
            max_severity = highest_severity([issue.severity for issue in issue_objs])

            for num in range(1, count + 1):
                group = CVEGroup()
                if id:
                    group.id = id if count <= 1 else '{}{}'.format(id, num)
                group.status = status if status else affected_to_status(Affected.affected, packages[0], fixed)
                group.severity = severity if severity else max_severity
                group.affected = affected
                group.fixed = fixed
                group.bug_ticket = bug_ticket
                group.reference = reference
                group.notes = notes
                group.created = created
                group.advisory_qualified = advisory_qualified

                db.session.add(group)
                db.session.commit()

                for issue in issue_objs:
                    db.get_or_create(CVEGroupEntry, group=group, cve=issue)
                for pkgname in packages:
                    db.get_or_create(CVEGroupPackage, pkgname=pkgname, group=group)
            db.session.commit()
            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


def create_advisory_content(id=DEFAULT_ADVISORY_ID, group=DEFAULT_GROUP_NAME, pkgname='foo', pkgver='1.1-1', cve='CVE-2012-1337', description='SNAFU', impact='Robots will take over', workaround='Update your machine', references=''):
    return f"""Arch Linux Security Advisory {id}
==========================================

Severity: Critical
Date    : 2012-12-21
CVE-ID  : {cve}
Package : {pkgname}
Type    : arbitrary code execution
Remote  : Yes
Link    : https://security.archlinux.org/{group}

Summary
=======

The package {pkgname} before version {pkgver} is vulnerable to arbitrary
code execution.

Resolution
==========

Upgrade to {pkgver}.

# pacman -Syu "{pkgname}>={pkgver}"

The problem has been fixed upstream in version {pkgver}.

Workaround
==========

{workaround}

Description
===========

{description}

Impact
======

{impact}

References
==========

https://security.archlinux.org/{group}
{references}
"""

DEFAULT_ADVISORY_CONTENT = create_advisory_content()


def create_advisory(func=None, id=DEFAULT_ADVISORY_ID, group_package_id=DEFAULT_GROUP_ID, advisory_type=None,
                    publication=Publication.scheduled, workaround=None, impact=None, content=None, created=datetime.utcnow(),
                    reference=None, count=1):
    def decorator(func):
        @wraps(func)
        def wrapper(db, *args, **kwargs):
            group_package = CVEGroupPackage.query.filter_by(id=group_package_id).first()
            issues = group_package.group.issues
            issue_types = list(set([issue.cve.issue_type for issue in issues]))
            issue_type = issue_types[0] if len(issue_types) == 1 else 'multiple issues'

            for num in range(1, count + 1):
                advisory = Advisory()
                advisory.id = id if count <= 1 else '{}{}'.format(id, num)
                advisory.group_package_id = group_package_id
                advisory.advisory_type = advisory_type if advisory_type else issue_type
                advisory.publication = publication
                advisory.workaround = workaround
                advisory.impact = impact
                advisory.content = content
                advisory.created = created
                advisory.reference = reference

                db.session.add(advisory)
            db.session.commit()
            func(db=db, *args, **kwargs)
        return wrapper
    if not func:
        return decorator
    return decorator(func)


def get_advisory(advisory_id=DEFAULT_ADVISORY_ID):
    return Advisory.query.get(advisory_id)


def advisory_count():
    return len(Advisory.query.all())
