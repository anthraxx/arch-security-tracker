from types import MethodType

from authlib.integrations.flask_client import OAuth
from flask import Blueprint
from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from sqlalchemy import event
from sqlalchemy import orm
from sqlalchemy.engine import Engine
from sqlalchemy.sql.expression import ClauseElement
from sqlalchemy_continuum import make_versioned
from sqlalchemy_continuum.plugins import FlaskPlugin
from sqlalchemy_continuum.plugins import PropertyModTrackerPlugin
from werkzeug.routing import BaseConverter

from config import FLASK_SESSION_PROTECTION
from config import FLASK_STRICT_TRANSPORT_SECURITY
from config import SQLALCHEMY_MIGRATE_REPO
from config import SQLITE_CACHE_SIZE
from config import SQLITE_JOURNAL_MODE
from config import SQLITE_MMAP_SIZE
from config import SQLITE_SYNCHRONOUS
from config import SQLITE_TEMP_STORE
from config import SSO_CLIENT_ID
from config import SSO_CLIENT_SECRET
from config import SSO_ENABLED
from config import SSO_METADATA_URL
from config import atom_feeds


@event.listens_for(Engine, 'connect')
def set_sqlite_pragma(dbapi_connection, connection_record):
    isolation_level = dbapi_connection.isolation_level
    dbapi_connection.isolation_level = None
    cursor = dbapi_connection.cursor()
    cursor.execute('PRAGMA temp_store = {}'.format(SQLITE_TEMP_STORE))
    cursor.execute('PRAGMA journal_mode = {}'.format(SQLITE_JOURNAL_MODE))
    cursor.execute('PRAGMA synchronous = {}'.format(SQLITE_SYNCHRONOUS))
    cursor.execute('PRAGMA mmap_size = {}'.format(SQLITE_MMAP_SIZE))
    cursor.execute('PRAGMA cache_size = {}'.format(SQLITE_CACHE_SIZE))
    cursor.execute('PRAGMA foreign_keys = ON')
    cursor.close()
    dbapi_connection.isolation_level = isolation_level


class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]


def db_get(self, model, defaults=None, **kwargs):
    return self.session.query(model).filter_by(**kwargs).first()


def db_create(self, model, defaults=None, **kwargs):
    params = dict((k, v) for k, v in kwargs.items() if not isinstance(v, ClauseElement))
    params.update(defaults or {})
    instance = model(**params)
    self.session.add(instance)
    self.session.flush()
    return instance


def db_get_or_create(self, model, defaults=None, **kwargs):
    instance = self.get(model, defaults, **kwargs)
    if instance:
        return instance
    return self.create(model, defaults, **kwargs)


csp = {
    'default-src': '\'self\'',
    'style-src': '\'self\'',
    'font-src': '\'self\'',
    'form-action': '\'self\''
}

db = SQLAlchemy()
db.get = MethodType(db_get, db)
db.create = MethodType(db_create, db)
db.get_or_create = MethodType(db_get_or_create, db)

make_versioned(plugins=[FlaskPlugin(), PropertyModTrackerPlugin()])
migrate = Migrate(db=db, directory=SQLALCHEMY_MIGRATE_REPO)
talisman = Talisman()
login_manager = LoginManager()
oauth = OAuth()
tracker = Blueprint('tracker', __name__)


def create_app(script_info=None):
    app = Flask(__name__)
    app.config.from_object('config')

    db.init_app(app)
    migrate.init_app(app)
    orm.configure_mappers()

    talisman.init_app(app,
                      force_https=False,
                      session_cookie_secure=False,
                      content_security_policy=csp,
                      strict_transport_security=FLASK_STRICT_TRANSPORT_SECURITY,
                      referrer_policy='no-referrer')

    login_manager.init_app(app)
    login_manager.session_protection = FLASK_SESSION_PROTECTION
    login_manager.login_view = 'tracker.login'

    app.url_map.converters['regex'] = RegexConverter
    app.jinja_env.globals['ATOM_FEEDS'] = atom_feeds

    if SSO_ENABLED:
        app.config["IDP_CLIENT_ID"] = SSO_CLIENT_ID
        app.config["IDP_CLIENT_SECRET"] = SSO_CLIENT_SECRET

        oauth.init_app(app)
        oauth.register(
            name='idp',
            server_metadata_url= SSO_METADATA_URL,
            client_kwargs={
                'scope': 'openid email'
            }
        )

    from tracker.view.error import error_handlers
    for error_handler in error_handlers:
        app.register_error_handler(error_handler['code_or_exception'], error_handler['func'])

    from tracker.view.blueprint import blueprint
    app.register_blueprint(tracker)
    app.register_blueprint(blueprint)

    @app.shell_context_processor
    def make_shell_context():
        from tracker.model import CVE
        from tracker.model import Advisory
        from tracker.model import CVEGroup
        from tracker.model import CVEGroupEntry
        from tracker.model import CVEGroupPackage
        from tracker.model import Package
        from tracker.model import User
        return dict(db=db, migrate=migrate, talisman=talisman, login_manager=login_manager, tracker=tracker,
                    Advisory=Advisory, CVE=CVE, CVEGroup=CVEGroup, CVEGroupEntry=CVEGroupEntry,
                    CVEGroupPackage=CVEGroupPackage, User=User, Package=Package, oauth=oauth)

    return app
