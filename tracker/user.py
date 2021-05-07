from base64 import b85encode
from functools import wraps
from os import urandom

from flask import redirect
from flask import url_for
from flask_login import current_user
from flask_login import login_required as flask_login_required
from scrypt import hash as shash
from sqlalchemy.exc import IntegrityError

from config import SSO_ENABLED
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import db
from tracker import login_manager
from tracker import oauth
from tracker.model.user import Guest
from tracker.model.user import User
from tracker.model.user import UserRole

login_manager.anonymous_user = Guest


def random_string(length=TRACKER_PASSWORD_LENGTH_MIN):
    salt = b85encode(urandom(length))
    return salt.decode()


def hash_password(password, salt):
    hashed = b85encode(shash(password, salt[:User.SALT_LENGTH]))
    return hashed.decode()[:User.PASSWORD_LENGTH]


@login_manager.user_loader
def load_user(session_token):
    if not session_token:
        return Guest()

    user = User.query.filter_by(token=session_token).first()
    if not user:
        return Guest()
    user.is_authenticated = True
    return user

def login_required(func):
    if SSO_ENABLED:
        @wraps(func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                redirect_url = url_for('tracker.sso_auth', _external=True)
                return oauth.idp.authorize_redirect(redirect_url)
            return func(*args, **kwargs)
        return wrapped 
    else:
        return flask_login_required(func)

def permission_required(permission):
    def decorator(func):
        @wraps(func)
        def decorated_view(*args, **kwargs):
            if not permission.fget(current_user.role):
                from tracker.view.error import forbidden
                return forbidden()
            return func(*args, **kwargs)
        return login_required(decorated_view)
    return decorator


def reporter_required(func):
    return permission_required(UserRole.is_reporter)(func)


def security_team_required(func):
    return permission_required(UserRole.is_security_team)(func)


def administrator_required(func):
    return permission_required(UserRole.is_administrator)(func)


def user_can_edit_issue(advisories=[]):
    role = current_user.role
    if not role.is_reporter:
        return False
    if role.is_security_team:
        return True
    return 0 == len(advisories)


def user_can_delete_issue(advisories=[]):
    role = current_user.role
    if not role.is_reporter:
        return False
    return 0 == len(advisories)


def user_can_edit_group(advisories=[]):
    return user_can_edit_issue(advisories)


def user_can_delete_group(advisories=[]):
    return user_can_delete_issue(advisories)


def user_can_handle_advisory():
    return current_user.role.is_security_team


def user_can_watch_log():
    return True


def user_can_watch_user_log():
    return current_user.role.is_reporter


def user_invalidate(user):
    user.token = None
    user.is_authenticated = False


def user_assign_new_token(user, max_tries=32):
    def assign_token(token):
        user.token = token
        return user
    return user_generate_new_token(assign_token, max_tries)


def user_generate_new_token(callback, max_tries=32):
    failed = 0
    while failed < max_tries:
        try:
            token = random_string(User.TOKEN_LENGTH)
            token_owners = User.query.filter_by(token=token).count()
            if 0 != token_owners:
                failed += 1
                continue
            user = callback(token)
            db.session.commit()
            return user
        except IntegrityError:
            db.session.rollback()
            failed += 1
    raise Exception('Failed to obtain unique token within {} tries'.format(max_tries))
