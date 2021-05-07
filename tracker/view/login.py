from flask import redirect
from flask import render_template
from flask import url_for
from flask_login import current_user
from flask_login import login_user
from flask_login import logout_user
from werkzeug.exceptions import Unauthorized

from config import SSO_ADMINISTRATOR_GROUP
from config import SSO_ENABLED
from config import SSO_GUEST_GROUP
from config import SSO_NEW_USER_DEFAULT_PASSWORD
from config import SSO_REPORTER_GROUP
from config import SSO_SECURITY_TEAM_GROUP
from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import oauth
from tracker import tracker
from tracker.form import LoginForm
from tracker.model.user import User
from tracker.user import user_assign_new_token
from tracker.user import user_invalidate

from ..model.enum import UserRole


@tracker.route('/login', methods=['GET', 'POST'])
def login():
    if SSO_ENABLED:
        return redirect(url_for('tracker.list_user'))
    else:
        if current_user.is_authenticated:
            return redirect(url_for('tracker.index'))

        form = LoginForm()
        if not form.validate_on_submit():
            status_code = Unauthorized.code if form.is_submitted() else 200
            return render_template('login.html',
                                title='Login',
                                form=form,
                                User=User,
                                password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                 'max': TRACKER_PASSWORD_LENGTH_MAX}), status_code

        user = user_assign_new_token(form.user)
        user.is_authenticated = True
        login_user(user)
        return redirect(url_for('tracker.index'))


@tracker.route('/logout', methods=['GET', 'POST'])
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for('tracker.index'))

    user_invalidate(current_user)
    logout_user()
    return redirect(url_for('tracker.index'))


@tracker.route('/sso-auth')
def sso_auth():
    from tracker import db

    token = oauth.idp.authorize_access_token()
    parsed_token = oauth.idp.parse_id_token(token)
    user_sub = parsed_token.get('sub')

    if not parsed_token.get('email_verified'):
        print("SSO error: user sub {} authenticated without a confirmed mail address".format(user_sub))
        return redirect(url_for('tracker.index'))

    user_email_idp = parsed_token.get('email')
    user = db.get(User, idp_id=user_sub)

    # the authenticated user does not have an IDP ID
    if user is None:
        user = db.get(User, email=user_email_idp) 
        
        # prevent impersonation by checking whether this email is associated with an IDP ID
        if user and user.idp_id is not None:
            print("SSO error: user sub {} tried to authenticate as {}".format(user_sub, user.email))
            return redirect(url_for('tracker.index'))

    user_groups = parsed_token.get('groups')
    user_groups_present = user_groups != None

    if not user_groups_present or len(user_groups) == 0:
        print("SSO error: user sub {} authenticated without any valid groups".format(user_sub))
        return redirect(url_for('tracker.index'))

    current_maximum_role = condense_user_groups_to_role(user_groups) if user_groups else UserRole.guest

    if user:
        user.role = current_maximum_role if user.role != current_maximum_role else user.role
        user.email = user_email_idp if user.email != user_email_idp else user.email
    else:
        from tracker.user import hash_password
        from tracker.user import random_string

        user = User()
        user.name = parsed_token.get('preferred_username', '')
        user.email = parsed_token.get('email')
        user.salt = random_string()
        user.password = hash_password(SSO_NEW_USER_DEFAULT_PASSWORD, user.salt)
        user.role = current_maximum_role
        user.active = True
        user.idp_id = user_sub
        db.session.add(user)

    db.session.commit()
    user = user_assign_new_token(user)
    user.is_authenticated = True
    login_user(user)

    return redirect(url_for('tracker.index'))

def condense_user_groups_to_role(idp_groups):
    group_names_for_roles = {
        SSO_ADMINISTRATOR_GROUP: UserRole.administrator,
        SSO_SECURITY_TEAM_GROUP: UserRole.security_team,
        SSO_GUEST_GROUP: UserRole.guest,
        SSO_REPORTER_GROUP: UserRole.reporter
    }

    eligible_roles = [group_names_for_roles[group] for group in idp_groups if group in group_names_for_roles]
    
    if len(eligible_roles) > 0:
        return sorted(eligible_roles, reverse=False)[0]
    else:
        return UserRole.guest
