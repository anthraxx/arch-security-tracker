from collections import OrderedDict
from collections import defaultdict

from flask import redirect
from flask import render_template
from flask import flash
from flask_login import current_user
from jinja2.utils import escape
from sqlalchemy import and_

from config import TRACKER_ADVISORY_URL
from config import TRACKER_BUGTRACKER_URL
from config import TRACKER_GROUP_URL
from config import TRACKER_ISSUE_URL
from config import TRACKER_SUMMARY_LENGTH_MAX
from tracker import db
from tracker import tracker
from tracker.advisory import advisory_escape_html
from tracker.advisory import advisory_extend_html
from tracker.advisory import advisory_format_issue_listing
from tracker.form.advisory import AdvisoryForm
from tracker.form.review import ReviewForm
from tracker.model import CVE
from tracker.model import Advisory
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model import Review
from tracker.model import User
from tracker.model.advisory import advisory_regex
from tracker.model.cve import cve_id_regex
from tracker.model.cvegroup import pkgname_regex
from tracker.model.cvegroup import vulnerability_group_regex
from tracker.model.enum import Publication
from tracker.model.enum import Remote
from tracker.model.enum import Status
from tracker.model.package import filter_duplicate_packages
from tracker.model.package import sort_packages
from tracker.user import user_can_delete_group
from tracker.user import user_can_delete_issue
from tracker.user import user_can_edit_group
from tracker.user import user_can_edit_issue
from tracker.user import user_can_handle_advisory
from tracker.util import json_response
from tracker.util import multiline_to_list
from tracker.view.error import not_found


def get_bug_project(databases):
    bug_project_mapping = {
        1: ['core', 'extra', 'testing'],
        5: ['community', 'community-testing', 'multilib', 'multilib-testing']
    }

    for category, repos in bug_project_mapping.items():
        if all((database in repos for database in databases)):
            return category

    # Fallback
    return 1


def get_bug_data(cves, pkgs, versions, group):
    references = []
    references = [ref for ref in multiline_to_list(group.reference)
                  if ref not in references]
    list(map(lambda issue: references.extend(
        [ref for ref in multiline_to_list(issue.reference) if ref not in references]), cves))

    severity_sorted_issues = sorted(cves, key=lambda issue: issue.issue_type)
    severity_sorted_issues = sorted(severity_sorted_issues, key=lambda issue: issue.severity)
    unique_issue_types = []
    for issue in severity_sorted_issues:
        if issue.issue_type not in unique_issue_types:
            unique_issue_types.append(issue.issue_type)

    bug_desc = render_template('bug.txt', cves=cves, group=group, references=references,
                               pkgs=pkgs, unique_issue_types=unique_issue_types,
                               TRACKER_ISSUE_URL=TRACKER_ISSUE_URL,
                               TRACKER_GROUP_URL=TRACKER_GROUP_URL)
    pkg_str = ' '.join((pkg.pkgname for pkg in pkgs))
    group_type = 'multiple issues' if len(unique_issue_types) > 1 else unique_issue_types[0]
    summary = '[{}] [Security] {} ({})'.format(pkg_str, group_type, ' '.join([cve.id for cve in cves]))

    if TRACKER_SUMMARY_LENGTH_MAX != 0 and len(summary) > TRACKER_SUMMARY_LENGTH_MAX:
        summary = "[{}] [Security] {} (Multiple CVE's)".format(pkg_str, group_type)

    # 5: critical, 4: high, 3: medium, 2: low, 1: very low.
    severitiy_mapping = {
        'unknown': 3,
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
    }

    task_severity = severitiy_mapping.get(group.severity.name)
    project = get_bug_project((pkg.database for pkg in versions))

    return {
        'project': project,
        'product_category': 13,  # security
        'item_summary': summary,
        'task_severity': task_severity,
        'detailed_desc': bug_desc
    }


def get_cve_data(cve):
    cve_model = CVE.query.get(cve)
    if not cve_model:
        return None

    entries = (db.session.query(CVEGroupEntry, CVEGroup, CVEGroupPackage, Advisory)
               .filter_by(cve=cve_model)
               .join(CVEGroup, CVEGroupEntry.group)
               .join(CVEGroupPackage, CVEGroup.packages)
               .outerjoin(Advisory, Advisory.group_package_id == CVEGroupPackage.id)
               .order_by(CVEGroup.created.desc()).order_by(CVEGroupPackage.pkgname)).all()

    group_packages = defaultdict(set)
    advisories = set()
    groups = set()
    for cve, group, pkg, advisory in entries:
        group_packages[group].add(pkg.pkgname)
        groups.add(group)
        if advisory:
            advisories.add(advisory)

    groups = sorted(groups, key=lambda item: item.created, reverse=True)
    groups = sorted(groups, key=lambda item: item.status)
    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)
    group_packages = dict(map(lambda item: (item[0], sorted(item[1])), group_packages.items()))

    return {'issue': cve_model,
            'groups': groups,
            'group_packages': group_packages,
            'advisories': advisories}


@tracker.route('/<regex("((issues?|cve)/)?"):path><regex("{}"):cve><regex("[./]json"):suffix>'.format(cve_id_regex[1:-1]), methods=['GET'])
@json_response
def show_cve_json(cve, path=None, suffix=None):
    data = get_cve_data(cve)
    if not data:
        return not_found(json=True)

    cve = data['issue']
    references = cve.reference.replace('\r', '').split('\n') if cve.reference else []
    packages = list(set(sorted([item for sublist in data['group_packages'].values() for item in sublist])))
    advisories = data['advisories']
    if not current_user.role.is_reporter:
        advisories = list(filter(lambda advisory: advisory.publication == Publication.published, advisories))

    json_data = OrderedDict()
    json_data['name'] = cve.id
    json_data['type'] = cve.issue_type
    json_data['severity'] = cve.severity.label
    json_data['vector'] = cve.remote.label
    json_data['description'] = cve.description
    json_data['groups'] = [str(group) for group in data['groups']]
    json_data['packages'] = packages
    json_data['advisories'] = [advisory.id for advisory in advisories]
    json_data['references'] = references
    json_data['notes'] = cve.notes if cve.notes else None
    return json_data


@tracker.route('/<regex("((issues?|cve)/)?"):path><regex("{}"):cve>'.format(cve_id_regex[1:]), methods=['GET'])
def show_cve(cve, path=None):
    data = get_cve_data(cve)
    if not data:
        return not_found()

    packages = list(set(sorted([item for sublist in data['group_packages'].values() for item in sublist])))
    title = '{} - {}'.format(data['issue'].id, ' '.join(packages)) \
            if len(packages) else \
            '{}'.format(data['issue'].id)

    advisories = data['advisories']
    if not current_user.role.is_reporter:
        advisories = list(filter(lambda advisory: advisory.publication == Publication.published, advisories))

    return render_template('cve.html',
                           title=title,
                           issue=data['issue'],
                           groups=data['groups'],
                           group_packages=data['group_packages'],
                           advisories=advisories,
                           can_edit=user_can_edit_issue(advisories),
                           can_delete=user_can_delete_issue(advisories))


def get_group_data(avg):
    avg_id = int(avg.replace('AVG-', ''))
    entries = (db.session.query(CVEGroup, CVE, CVEGroupPackage, Advisory, Package)
               .filter(CVEGroup.id == avg_id)
               .join(CVEGroupEntry, CVEGroup.issues)
               .join(CVE, CVEGroupEntry.cve)
               .join(CVEGroupPackage, CVEGroup.packages)
               .outerjoin(Package, Package.name == CVEGroupPackage.pkgname)
               .outerjoin(Advisory, Advisory.group_package_id == CVEGroupPackage.id)).all()
    if not entries:
        return None

    group = None
    issues = set()
    packages = set()
    advisories = set()
    issue_types = set()
    versions = set()
    for group_entry, cve, pkg, advisory, package in entries:
        group = group_entry
        issues.add(cve)
        issue_types.add(cve.issue_type)
        packages.add(pkg)
        if package:
            versions.add(package)
        if advisory:
            advisories.add(advisory)

    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)
    issue_types = list(issue_types)
    issues = sorted(issues, key=lambda item: item, reverse=True)
    packages = sorted(packages, key=lambda item: item.pkgname)
    versions = filter_duplicate_packages(sort_packages(list(versions)), True)
    advisories_pending = group.status == Status.fixed and group.advisory_qualified and len(advisories) <= 0

    return {
        'group': group,
        'packages': packages,
        'versions': versions,
        'issues': issues,
        'issue_types': issue_types,
        'advisories': advisories,
        'advisories_pending': advisories_pending
    }


@tracker.route('/group/<regex("{}"):avg><regex("[./]json"):postfix>'.format(vulnerability_group_regex[1:-1]), methods=['GET'])
@tracker.route('/avg/<regex("{}"):avg><regex("[./]json"):postfix>'.format(vulnerability_group_regex[1:-1]), methods=['GET'])
@tracker.route('/<regex("{}"):avg><regex("[./]json"):postfix>'.format(vulnerability_group_regex[1:-1]), methods=['GET'])
@json_response
def show_group_json(avg, postfix=None):
    data = get_group_data(avg)
    if not data:
        return not_found(json=True)

    group = data['group']
    advisories = data['advisories']
    if not current_user.role.is_reporter:
        advisories = list(filter(lambda advisory: advisory.publication == Publication.published, advisories))
    issues = data['issues']
    packages = data['packages']
    issue_types = data['issue_types']
    references = group.reference.replace('\r', '').split('\n') if group.reference else []

    json_data = OrderedDict()
    json_data['name'] = group.name
    json_data['packages'] = [package.pkgname for package in packages]
    json_data['status'] = group.status.label
    json_data['severity'] = group.severity.label
    json_data['type'] = 'multiple issues' if len(issue_types) > 1 else issue_types[0]
    json_data['affected'] = group.affected
    json_data['fixed'] = group.fixed if group.fixed else None
    json_data['ticket'] = group.bug_ticket if group.bug_ticket else None
    json_data['issues'] = [str(cve) for cve in issues]
    json_data['advisories'] = [advisory.id for advisory in advisories]
    json_data['references'] = references
    json_data['notes'] = group.notes if group.notes else None

    return json_data


@tracker.route('/group/<regex("{}"):avg>'.format(vulnerability_group_regex[1:]), methods=['GET'])
@tracker.route('/avg/<regex("{}"):avg>'.format(vulnerability_group_regex[1:]), methods=['GET'])
@tracker.route('/<regex("{}"):avg>'.format(vulnerability_group_regex[1:]), methods=['GET'])
def show_group(avg):
    data = get_group_data(avg)
    if not data:
        return not_found()

    group = data['group']
    advisories = data['advisories']
    if not current_user.role.is_reporter:
        advisories = list(filter(lambda advisory: advisory.publication == Publication.published, advisories))
    issues = data['issues']
    packages = data['packages']
    issue_types = data['issue_types']
    versions = data['versions']
    issue_type = 'multiple issues' if len(issue_types) > 1 else issue_types[0]
    pkgnames = list(set(sorted([pkg.pkgname for pkg in packages])))

    form = AdvisoryForm()
    form.advisory_type.data = issue_type

    return render_template('group.html',
                           title='{} - {}'.format(group, ' '.join(pkgnames)),
                           form=form,
                           group=group,
                           packages=packages,
                           issues=issues,
                           advisories=advisories,
                           versions=versions,
                           Status=Status,
                           issue_type=issue_type,
                           bug_data=get_bug_data(issues, packages, versions, group),
                           advisories_pending=data['advisories_pending'],
                           can_edit=user_can_edit_group(advisories),
                           can_delete=user_can_delete_group(advisories),
                           can_handle_advisory=user_can_handle_advisory())


def get_package_data(pkgname):
    entries = (db.session.query(Package, CVEGroup, CVE, Advisory)
               .filter(Package.name == pkgname)
               .outerjoin(CVEGroupPackage, CVEGroupPackage.pkgname == Package.name)
               .outerjoin(CVEGroup, CVEGroupPackage.group)
               .outerjoin(CVEGroupEntry, CVEGroup.issues)
               .outerjoin(CVE, CVEGroupEntry.cve)
               .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                         Advisory.publication == Publication.published))
               ).all()

    # fallback for dropped packages
    if not entries:
        entries = (db.session.query(CVEGroupPackage, CVEGroup, CVE, Advisory)
                   .filter(CVEGroupPackage.pkgname == pkgname)
                   .join(CVEGroup, CVEGroupPackage.group)
                   .join(CVEGroupEntry, CVEGroup.issues)
                   .join(CVE, CVEGroupEntry.cve)
                   .outerjoin(Advisory, and_(Advisory.group_package_id == CVEGroupPackage.id,
                                             Advisory.publication == Publication.published))
                   ).all()

    if not entries:
        return None

    groups = set()
    issues = set()
    advisories = set()
    versions = set()
    for package, group, cve, advisory in entries:
        if isinstance(package, Package):
            versions.add(package)
        if group:
            groups.add(group)
        if cve:
            issues.add((cve, group))
        if advisory:
            advisories.add(advisory)

    issues = [{'issue': e[0], 'group': e[1]} for e in issues]
    issues = sorted(issues, key=lambda item: item['issue'], reverse=True)
    issues = sorted(issues, key=lambda item: item['group'].status)
    groups = sorted(groups, key=lambda item: item.id, reverse=True)
    groups = sorted(groups, key=lambda item: item.status)
    advisories = sorted(advisories, key=lambda item: item.id, reverse=True)
    versions = filter_duplicate_packages(sort_packages(list(versions)), True)
    package = versions[0] if versions else None

    return {
        'package': package,
        'pkgname': pkgname,
        'versions': versions,
        'groups': groups,
        'issues': issues,
        'advisories': advisories
    }


@tracker.route('/package/<regex("{}"):pkgname><regex("[./]json"):suffix>'.format(pkgname_regex[1:-1]), methods=['GET'])
@json_response
def show_package_json(pkgname, suffix=None):
    data = get_package_data(pkgname)
    if not data:
        return not_found(json=True)

    advisories = data['advisories']
    versions = data['versions']
    groups = data['groups']
    issues = data['issues']

    json_advisory = []
    for advisory in advisories:
        entry = OrderedDict()
        entry['name'] = advisory.id
        entry['date'] = advisory.created.strftime('%Y-%m-%d')
        entry['severity'] = advisory.group_package.group.severity.label
        entry['type'] = advisory.advisory_type
        entry['reference'] = advisory.reference if advisory.reference else None
        json_advisory.append(entry)

    json_versions = []
    for version in versions:
        entry = OrderedDict()
        entry['version'] = version.version
        entry['database'] = version.database
        json_versions.append(entry)

    json_groups = []
    for group in groups:
        entry = OrderedDict()
        entry['name'] = group.name
        entry['status'] = group.status.label
        entry['severity'] = group.severity.label
        json_groups.append(entry)

    json_issues = []
    for issue in issues:
        group = issue['group']
        issue = issue['issue']
        entry = OrderedDict()
        entry['name'] = issue.id
        entry['severity'] = issue.severity.label
        entry['type'] = issue.issue_type
        entry['status'] = group.status.label
        json_issues.append(entry)

    json_data = OrderedDict()
    json_data['name'] = pkgname
    json_data['versions'] = json_versions
    json_data['advisories'] = json_advisory
    json_data['groups'] = json_groups
    json_data['issues'] = json_issues
    return json_data


@tracker.route('/package/<regex("{}"):pkgname>'.format(pkgname_regex[1:]), methods=['GET'])
def show_package(pkgname):
    data = get_package_data(pkgname)
    if not data:
        return not_found()

    groups = data['groups']
    data['groups'] = {'open': list(filter(lambda group: group.status.open(), groups)),
                      'resolved': list(filter(lambda group: group.status.resolved(), groups))}

    issues = data['issues']
    data['issues'] = {'open': list(filter(lambda issue: issue['group'].status.open(), issues)),
                      'resolved': list(filter(lambda issue: issue['group'].status.resolved(), issues))}

    return render_template('package.html',
                           title='{}'.format(pkgname),
                           package=data)


def render_html_advisory(advisory, package, group, raw_asa, generated, form=None, reviews=[]):
    return render_template('advisory.html',
                           title='[{}] {}: {}'.format(advisory.id, package.pkgname, advisory.advisory_type),
                           advisory=advisory,
                           package=package,
                           raw_asa=raw_asa,
                           generated=generated,
                           current_user=current_user,
                           form=form,
                           reviews=reviews,
                           Review=Review,
                           can_handle_advisory=user_can_handle_advisory(),
                           Publication=Publication)


@tracker.route('/advisory/<regex("{}"):advisory_id>/raw'.format(advisory_regex[1:-1]), methods=['GET'])
@tracker.route('/<regex("{}"):advisory_id>/raw'.format(advisory_regex[1:-1]), methods=['GET'])
def show_advisory_raw(advisory_id):
    result = show_advisory(advisory_id, raw=True)
    if isinstance(result, tuple):
        return result
    if not isinstance(result, str):
        return result
    return result, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@tracker.route('/advisory/<regex("{}"):advisory_id>/generate/raw'.format(advisory_regex[1:-1]), methods=['GET'])
@tracker.route('/<regex("{}"):advisory_id>/generate/raw'.format(advisory_regex[1:-1]), methods=['GET'])
def show_generated_advisory_raw(advisory_id):
    result = show_generated_advisory(advisory_id, raw=True)
    if isinstance(result, tuple):
        return result
    if not isinstance(result, str):
        return result
    return result, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@tracker.route('/advisory/<regex("{}"):advisory_id>'.format(advisory_regex[1:]), methods=['GET'])
@tracker.route('/<regex("{}"):advisory_id>'.format(advisory_regex[1:]), methods=['GET'])
def show_advisory(advisory_id, raw=False):
    entries = (db.session.query(Advisory, CVEGroup, CVEGroupPackage, CVE)
               .filter(Advisory.id == advisory_id)
               .join(CVEGroupPackage, Advisory.group_package)
               .join(CVEGroup, CVEGroupPackage.group)
               .join(CVEGroupEntry, CVEGroup.issues)
               .join(CVE, CVEGroupEntry.cve)
               .order_by(CVE.id)
               ).all()
    if not entries:
        return not_found()

    advisory = entries[0][0]
    group = entries[0][1]
    package = entries[0][2]
    issues = [issue for (advisory, group, package, issue) in entries]

    if not advisory.content:
        if raw:
            return redirect('/{}/generate/raw'.format(advisory_id))
        return redirect('/{}/generate'.format(advisory_id))

    if raw:
        return advisory.content
    asa = advisory_extend_html(advisory_escape_html(advisory.content), issues, package)
    return render_html_advisory(advisory=advisory, package=package, group=group, raw_asa=asa, generated=False)


@tracker.route('/advisory/<regex("{}"):advisory_id>/generate'.format(advisory_regex[1:-1]), methods=['GET', 'POST'])
@tracker.route('/<regex("{}"):advisory_id>/generate'.format(advisory_regex[1:-1]), methods=['GET', 'POST'])
def show_generated_advisory(advisory_id, raw=False):
    entries = (db.session.query(Advisory, CVEGroup, CVEGroupPackage, CVE)
               .filter(Advisory.id == advisory_id)
               .join(CVEGroupPackage, Advisory.group_package)
               .join(CVEGroup, CVEGroupPackage.group)
               .join(CVEGroupEntry, CVEGroup.issues)
               .join(CVE, CVEGroupEntry.cve)
               .order_by(CVE.id)
               ).all()
    if not entries:
        return not_found()

    advisory = entries[0][0]

    form = ReviewForm()
    review = (db.session.query(Review, Advisory, User)
               .filter(Advisory.id == advisory_id)
               .filter(User.id == current_user.id)
               .join(Advisory).join(User)).first()
    if not form.is_submitted() and review:
        form.note.data = review[0].note
    if form.is_submitted():
        if not form.validate_on_submit():
            flash("Need to write feedback to disapprove", 'warning')
            return redirect('/{}/generate'.format(advisory.id))
        if review:
            db.session.delete(review[0])
            db.session.commit()
        db.create(Review,
                approved=form.approve.data,
                advisory=advisory,
                user=current_user,
                note=form.note.data)
        flash("Added review!")

    reviews = (db.session.query(Review, Advisory, User)
               .filter(Advisory.id == advisory_id)
               .join(Advisory).join(User)).all()
    all_reviews = [review for (review, advisory, user) in reviews]
    group = entries[0][1]
    package = entries[0][2]
    issues = sorted([issue for (advisory, group, package, issue) in entries])
    severity_sorted_issues = sorted(issues, key=lambda issue: issue.issue_type)
    severity_sorted_issues = sorted(severity_sorted_issues, key=lambda issue: issue.severity)
    remote = any([issue.remote is Remote.remote for issue in issues])
    issue_listing_formatted = advisory_format_issue_listing([issue.id for issue in issues])

    link = TRACKER_ADVISORY_URL.format(advisory.id, group.id)
    upstream_released = group.affected.split('-')[0].split('+')[0] != group.fixed.split('-')[0].split('+')[0]
    upstream_version = group.fixed.split('-')[0].split('+')[0]
    if ':' in upstream_version:
        upstream_version = upstream_version[upstream_version.index(':') + 1:]
    unique_issue_types = []
    for issue in severity_sorted_issues:
        if issue.issue_type not in unique_issue_types:
            unique_issue_types.append(issue.issue_type)

    references = []
    if group.bug_ticket:
        references.append(TRACKER_BUGTRACKER_URL.format(group.bug_ticket))
    references.extend([ref for ref in multiline_to_list(group.reference)
                       if ref not in references])
    list(map(lambda issue: references.extend(
        [ref for ref in multiline_to_list(issue.reference) if ref not in references]), issues))

    raw_asa = render_template('advisory.txt',
                              advisory=advisory,
                              group=group,
                              package=package,
                              issues=issues,
                              remote=remote,
                              issue_listing_formatted=issue_listing_formatted,
                              link=link,
                              workaround=advisory.workaround,
                              impact=advisory.impact,
                              upstream_released=upstream_released,
                              upstream_version=upstream_version,
                              unique_issue_types=unique_issue_types,
                              references=references,
                              TRACKER_ISSUE_URL=TRACKER_ISSUE_URL,
                              TRACKER_GROUP_URL=TRACKER_GROUP_URL)
    if raw:
        return raw_asa

    raw_asa = '\n'.join(raw_asa.split('\n')[2:])
    raw_asa = str(escape(raw_asa))
    raw_asa = advisory_extend_html(raw_asa, issues, package)
    return render_html_advisory(advisory=advisory, package=package, group=group, raw_asa=raw_asa, generated=True,
            form=form, reviews=all_reviews)
