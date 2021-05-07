from configparser import ConfigParser
from glob import glob
from os import environ
from os.path import abspath
from os.path import dirname

basedir = abspath(dirname(__file__))

config = ConfigParser()
config_files = sorted(glob('{}/config/*.conf'.format(basedir)))
for config_file in config_files:
    config.read(config_file)

atom_feeds = []


def get_debug_flag():
    return config_flask.getboolean('debug')


def set_debug_flag(debug):
    global FLASK_DEBUG
    FLASK_DEBUG = debug
    environ.setdefault('FLASK_DEBUG', '1' if FLASK_DEBUG else '0')
    config_flask['debug'] = 'on' if debug else 'off'


config_tracker = config['tracker']
TRACKER_ADVISORY_URL = config_tracker['advisory_url']
TRACKER_BUGTRACKER_URL = config_tracker['bugtracker_url']
TRACKER_MAILMAN_URL = config_tracker['mailman_url']
TRACKER_GROUP_URL = config_tracker['group_url']
TRACKER_ISSUE_URL = config_tracker['issue_url']
TRACKER_PASSWORD_LENGTH_MIN = config_tracker.getint('password_length_min')
TRACKER_PASSWORD_LENGTH_MAX = config_tracker.getint('password_length_max')
TRACKER_SUMMARY_LENGTH_MAX = config_tracker.getint('summary_length_max')
TRACKER_LOG_ENTRIES_PER_PAGE = config_tracker.getint('log_entries_per_page')

config_sqlite = config['sqlite']
SQLITE_JOURNAL_MODE = config_sqlite['journal_mode']
SQLITE_TEMP_STORE = config_sqlite['temp_store']
SQLITE_SYNCHRONOUS = config_sqlite['synchronous']
SQLITE_MMAP_SIZE = config_sqlite.getint('mmap_size')
SQLITE_CACHE_SIZE = config_sqlite.getint('cache_size')

config_sqlalchemy = config['sqlalchemy']
SQLALCHEMY_DATABASE_URI = config_sqlalchemy['database_uri'].replace('{{BASEDIR}}', basedir)
SQLALCHEMY_MIGRATE_REPO = config_sqlalchemy['migrate_repo'].replace('{{BASEDIR}}', basedir)
SQLALCHEMY_ECHO = config_sqlalchemy.getboolean('echo')
SQLALCHEMY_TRACK_MODIFICATIONS = config_sqlalchemy.getboolean('track_modifications')

config_flask = config['flask']
CSRF_ENABLED = config_flask.getboolean('csrf')
SECRET_KEY = config_flask['secret_key']
FLASK_HOST = config_flask['host']
FLASK_PORT = config_flask.getint('port')
FLASK_SESSION_PROTECTION = None if 'none' == config_flask['session_protection'] else config_flask['session_protection']
set_debug_flag(config_flask.getboolean('debug'))
FLASK_STRICT_TRANSPORT_SECURITY = config_flask.getboolean('strict_transport_security')
SESSION_COOKIE_SAMESITE = config_flask['session_cookie_samesite']

config_pacman = config['pacman']
PACMAN_HANDLE_CACHE_TIME = config_pacman.getint('handle_cache_time')

config_sso = config['sso']
SSO_ENABLED = config_sso.getboolean('enabled')
SSO_CLIENT_SECRET = config_sso.get('client_secret')
SSO_CLIENT_ID = config_sso.get('client_id')
SSO_NEW_USER_DEFAULT_PASSWORD = config_sso.get('new_user_default_password')
SSO_ADMINISTRATOR_GROUP = config_sso.get('administrator_group')
SSO_SECURITY_TEAM_GROUP = config_sso.get('security_team_group')
SSO_REPORTER_GROUP = config_sso.get('reporter_group')
SSO_GUEST_GROUP = config_sso.get('guest_group')
SSO_METADATA_URL = config_sso.get('metadata_url')