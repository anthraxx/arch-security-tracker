from flask import flash
from flask import redirect
from flask import render_template
from flask_login import current_user

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import db
from tracker import tracker
from tracker.form.admin import UserForm
from tracker.form.confirm import ConfirmForm
from tracker.model.enum import UserRole
from tracker.model.user import Guest
from tracker.model.user import User
from tracker.model.user import username_regex
from tracker.user import administrator_required
from tracker.user import hash_password
from tracker.user import random_string
from tracker.user import user_invalidate
from tracker.view.error import forbidden
from tracker.view.error import not_found

from ..user import login_required


@tracker.route('/admin', methods=['GET', 'POST'])
@tracker.route('/user', methods=['GET', 'POST'])
@login_required
def list_user():
    users = User.query.order_by(User.name).all()
    users = sorted(users, key=lambda u: u.name)

    if not current_user.role.is_administrator:
        masked = []
        for user in users:
            guest = Guest()
            guest.name = user.name
            guest.email = user.email
            guest.role = user.role if not user.role.is_administrator else UserRole.security_team
            guest.active = user.active
            if user.active:
                masked.append(guest)
        users = masked

    users = sorted(users, key=lambda u: u.role)
    return render_template('admin/user.html',
                           title='User list',
                           users=users)


@tracker.route('/user/create', methods=['GET', 'POST'])
@administrator_required
def create_user():
    form = UserForm()
    if not form.validate_on_submit():
        return render_template('admin/form/user.html',
                               title='Create user',
                               form=form,
                               User=User,
                               password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                'max': TRACKER_PASSWORD_LENGTH_MAX})

    password = random_string() if not form.password.data else form.password.data
    salt = random_string()

    user = db.create(User,
                     name=form.username.data,
                     email=form.email.data,
                     salt=salt,
                     password=hash_password(password, salt),
                     role=UserRole.fromstring(form.role.data),
                     active=form.active.data)
    db.session.commit()

    flash('Created user {} with password {}'.format(user.name, password))
    return redirect('/user')


@tracker.route('/user/<regex("{}"):username>/edit'.format(username_regex[1:-1]), methods=['GET', 'POST'])
@administrator_required
def edit_user(username):
    own_user = username == current_user.name
    if not current_user.role.is_administrator and not own_user:
        forbidden()

    user = User.query.filter_by(name=username).first()
    if not user:
        return not_found()

    form = UserForm(edit=True)
    if not form.is_submitted():
        form.username.data = user.name
        form.email.data = user.email
        form.role.data = user.role.name
        form.active.data = user.active
    if not form.validate_on_submit():
        return render_template('admin/form/user.html',
                               title='Edit {}'.format(username),
                               form=form,
                               User=User,
                               random_password=True,
                               password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                'max': TRACKER_PASSWORD_LENGTH_MAX})

    active_admins = User.query.filter_by(active=True, role=UserRole.administrator).count()
    if user.id == current_user.id and 1 == active_admins and not form.active.data:
        return forbidden()

    user.name = form.username.data
    user.email = form.email.data
    user.role = UserRole.fromstring(form.role.data)
    if form.random_password.data:
        form.password.data = random_string()
    if 0 != len(form.password.data):
        user.salt = random_string()
        user.password = hash_password(form.password.data, user.salt)
    user.active = form.active.data
    user_invalidate(user)
    db.session.commit()

    flash_password = ''
    if form.random_password.data:
        flash_password = ' with password {}'.format(form.password.data)
    flash('Edited user {}{}'.format(user.name, flash_password))
    return redirect('/user')


@tracker.route('/user/<regex("{}"):username>/delete'.format(username_regex[1:-1]), methods=['GET', 'POST'])
@administrator_required
def delete_user(username):
    user = User.query.filter_by(name=username).first()
    if not user:
        return not_found()

    form = ConfirmForm()
    title = 'Delete {}'.format(username)
    if not form.validate_on_submit():
        return render_template('admin/form/delete_user.html',
                               title=title,
                               heading=title,
                               form=form,
                               user=user)

    if not form.confirm.data:
        return redirect('/user')

    active_admins = User.query.filter_by(active=True, role=UserRole.administrator).count()
    if user.id == current_user.id and 1 >= active_admins:
        return forbidden()

    user_invalidate(user)
    db.session.delete(user)
    db.session.commit()
    flash('Deleted user {}'.format(user.name))
    return redirect('/user')
