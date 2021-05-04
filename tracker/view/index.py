from collections import OrderedDict
from collections import defaultdict

from flask import render_template
from sqlalchemy import and_
from sqlalchemy import func

from tracker import db
from tracker import tracker
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model.enum import Publication
from tracker.model.enum import Status
from tracker.util import json_response


def get_index_data(only_vulnerable=False, only_in_repo=True):
    select = (db.session.query(CVEGroup, CVE, func.group_concat(CVEGroupPackage.pkgname, ' '),
                               func.group_concat(Advisory.id, ' '))
                        .join(CVEGroupEntry, CVEGroup.issues)
                        .join(CVE, CVEGroupEntry.cve)
                        .join(CVEGroupPackage, CVEGroup.packages)
                        .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                                  Advisory.publication == Publication.published)))
    if only_vulnerable:
        select = select.filter(CVEGroup.status.in_([Status.unknown, Status.vulnerable, Status.testing]))
    if only_in_repo:
        select = select.join(Package, Package.name == CVEGroupPackage.pkgname)

    entries = (select.group_by(CVEGroup.id).group_by(CVE.id)
                     .order_by(CVEGroup.status.desc())
                     .order_by(CVEGroup.changed.desc())).all()

    groups = defaultdict(defaultdict)
    for group, cve, pkgs, advisories in entries:
        group_entry = groups.setdefault(group.id, {})
        group_entry['group'] = group
        group_entry['pkgs'] = list(set(pkgs.split(' ')))
        group_entry['advisories'] = advisories.split(' ') if advisories else []
        group_entry.setdefault('issues', []).append(cve)

    for key, group in groups.items():
        group['issues'] = sorted(group['issues'], key=lambda item: item.id, reverse=True)

    groups = groups.values()
    groups = sorted(groups, key=lambda item: item['group'].changed, reverse=True)
    groups = sorted(groups, key=lambda item: item['group'].severity)
    groups = sorted(groups, key=lambda item: item['group'].status)
    return groups


def index(only_vulnerable=True, path=None):
    groups = get_index_data(only_vulnerable)
    return render_template('index.html',
                           title='Issues' if not only_vulnerable else 'Vulnerable issues',
                           entries=groups,
                           only_vulnerable=only_vulnerable)


@tracker.route('/<regex("issues(/(open|vulnerable))?"):path>', defaults={'path': 'issues'}, methods=['GET'])
def index_vulnerable(path=None):
    return index(only_vulnerable=True)


@tracker.route('/<regex("(issues/)?all"):path>', defaults={'path': 'issues/all'}, methods=['GET'])
def index_all(path=None):
    return index(only_vulnerable=False)


# TODO: temporarily keep /json this way until tools adopted new endpoint
@tracker.route('/json', defaults={'path': 'json', 'only_vulnerable': False}, methods=['GET'])
@tracker.route('/<regex("(issues/?)?(all)?.json"):path>', defaults={'path': 'all.json', 'only_vulnerable': False}, methods=['GET'])
@json_response
def index_json(only_vulnerable=False, path=None):
    entries = get_index_data(only_vulnerable)
    json_data = []
    for entry in entries:
        group = entry['group']
        types = list(set([cve.issue_type for cve in entry['issues']]))

        json_entry = OrderedDict()
        json_entry['name'] = group.name
        json_entry['packages'] = entry['pkgs']
        json_entry['status'] = group.status.label
        json_entry['severity'] = group.severity.label
        json_entry['type'] = 'multiple issues' if len(types) > 1 else types[0]
        json_entry['affected'] = group.affected
        json_entry['fixed'] = group.fixed if group.fixed else None
        json_entry['ticket'] = group.bug_ticket if group.bug_ticket else None
        json_entry['issues'] = [str(cve) for cve in entry['issues']]
        json_entry['advisories'] = entry['advisories']
        json_data.append(json_entry)
    return json_data


@tracker.route('/<regex("(issues/?)?(open|vulnerable).json"):path>', methods=['GET'])
def index_vulnerable_json(path=None):
    return index_json(only_vulnerable=True)
