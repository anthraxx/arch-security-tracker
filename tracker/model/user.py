from tracker import db

from .enum import UserRole

username_regex = r'^([\w]+)$'


class User(db.Model):

    NAME_LENGTH = 32
    EMAIL_LENGTH = 128
    SALT_LENGTH = 20
    PASSWORD_LENGTH = 80
    TOKEN_LENGTH = 120

    __tablename__ = 'user'
    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    name = db.Column(db.String(NAME_LENGTH), index=True, unique=True, nullable=False)
    email = db.Column(db.String(EMAIL_LENGTH), index=True, unique=True, nullable=False)
    salt = db.Column(db.String(SALT_LENGTH), nullable=False)
    password = db.Column(db.String(SALT_LENGTH), nullable=False)
    token = db.Column(db.String(TOKEN_LENGTH), index=True, unique=True, nullable=True)
    role = db.Column(UserRole.as_type(), nullable=False, default=UserRole.reporter)
    active = db.Column(db.Boolean(), nullable=False, default=True)
    idp_id = db.Column(db.String(40), nullable=True, default=None)

    is_authenticated = False
    is_anonymous = False

    @property
    def is_active(self):
        return self.active

    def get_id(self):
        return '{}'.format(self.token)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<User %r>' % (self.name)


class Guest(User):
    def __init__(self):
        super().__init__()
        self.name = 'Guest'
        self.id = -42
        self.active = False
        self.is_anonymous = True
        self.is_authenticated = False
        self.role = UserRole.guest

    def get_id(self):
        return None
