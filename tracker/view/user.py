from flask import flash
from flask import redirect
from flask import render_template
from flask_login import current_user
from flask_login import login_required
from sqlalchemy_continuum import version_class
from sqlalchemy_continuum import versioning_manager

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import db
from tracker import tracker
from tracker.form.user import UserPasswordForm
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import User
from tracker.model.user import username_regex
from tracker.user import hash_password
from tracker.user import random_string


@tracker.route('/profile', methods=['GET', 'POST'])
@login_required
def edit_own_user_profile():
    form = UserPasswordForm()
    if not form.validate_on_submit():
        return render_template('form/profile.html',
                               title='Edit profile',
                               form=form,
                               password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                'max': TRACKER_PASSWORD_LENGTH_MAX})

    user = current_user
    user.salt = random_string()
    user.password = hash_password(form.password.data, user.salt)
    db.session.commit()

    flash('Profile saved')
    return redirect('/')


# TODO: define permission to view this
@tracker.route('/user/<regex("{}"):username>/log'.format(username_regex[1:-1]), defaults={'page': 1}, methods=['GET'])
@tracker.route('/user/<regex("{}"):username>/log/page/<int(min=1):page>'.format(username_regex[1:-1]), methods=['GET'])
@login_required
def show_user_log(username, page=1):
    MAX_ENTRIES_PER_PAGE = 10
    Transaction = versioning_manager.transaction_cls
    VersionClassCVE = version_class(CVE)
    VersionClassGroup = version_class(CVEGroup)
    VersionClassAdvisory = version_class(Advisory)

    pagination = (db.session.query(Transaction, VersionClassCVE, VersionClassGroup, VersionClassAdvisory)
                  .outerjoin(VersionClassCVE, Transaction.id == VersionClassCVE.transaction_id)
                  .outerjoin(VersionClassGroup, Transaction.id == VersionClassGroup.transaction_id)
                  .outerjoin(VersionClassAdvisory, Transaction.id == VersionClassAdvisory.transaction_id)
                  .join(User)
                  .filter(User.name == username)
                  .order_by(Transaction.issued_at.desc())
                  ).paginate(page, MAX_ENTRIES_PER_PAGE, True)

    return render_template('log/log.html',
                           title=f'User {username} - log',
                           username=username,
                           pagination=pagination,
                           CVE=CVE,
                           CVEGroup=CVEGroup)
