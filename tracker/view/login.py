from flask import redirect
from flask import render_template
from flask import url_for
from flask_login import current_user
from flask_login import login_user
from flask_login import logout_user
from werkzeug.exceptions import Unauthorized

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import tracker
from tracker.form import LoginForm
from tracker.model.user import User
from tracker.user import user_assign_new_token
from tracker.user import user_invalidate


@tracker.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('tracker.index_vulnerable'))

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
    return redirect(url_for('tracker.index_vulnerable'))


@tracker.route('/logout', methods=['GET', 'POST'])
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for('tracker.index_vulnerable'))

    user_invalidate(current_user)
    logout_user()
    return redirect(url_for('tracker.index_vulnerable'))
