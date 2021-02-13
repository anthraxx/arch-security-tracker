from flask import flash
from flask import redirect
from flask import render_template

from tracker import db
from tracker import tracker
from tracker.form import CVEForm
from tracker.form import GroupForm
from tracker.model import CVE
from tracker.model import CVEGroup
from tracker.model import CVEGroupEntry
from tracker.model import CVEGroupPackage
from tracker.model import Package
from tracker.model.enum import Affected
from tracker.model.enum import Remote
from tracker.model.enum import Severity
from tracker.model.enum import Status
from tracker.model.enum import affected_to_status
from tracker.model.enum import highest_severity
from tracker.user import reporter_required
from tracker.util import multiline_to_list

ERROR_GROUP_WITH_ISSUE_EXISTS = 'The group AVG-{} already contains {} for the package {}'
ERROR_OPEN_GROUP_EXISTS = 'The group AVG-{} already has open issues for the package {}'
CVE_MERGED = 'Merged existing {} with the provided data'
CVE_MERGED_PARTIALLY = 'Failed to fully merge {}, check the following fields: {}'
ERROR_UNMERGEABLE = 'Unmergeable field, old value shown'


@tracker.route('/cve/add', methods=['GET', 'POST'])
@reporter_required
def add_cve():
    form = CVEForm()
    if not form.validate_on_submit():
        return render_template('form/cve.html',
                               title='Add CVE',
                               form=form,
                               CVE=CVE)

    cve = db.get(CVE, id=form.cve.data)
    if cve is not None:
        not_merged = []
        merged = False

        # try to merge issue_type
        if 'unknown' != form.issue_type.data:
            if 'unknown' == cve.issue_type:
                cve.issue_type = form.issue_type.data
                merged = True
            elif form.issue_type.data != cve.issue_type:
                not_merged.append(form.issue_type)
        form.issue_type.data = cve.issue_type

        # try to merge severity
        form_severity = Severity.fromstring(form.severity.data)
        if Severity.unknown != form_severity:
            if Severity.unknown == cve.severity:
                cve.severity = form_severity
                merged = True
            elif form_severity != cve.severity:
                not_merged.append(form.severity)
        form.severity.data = cve.severity.name

        # try to merge remote
        form_remote = Remote.fromstring(form.remote.data)
        if Remote.unknown != form_remote:
            if Remote.unknown == cve.remote:
                cve.remote = form_remote
                merged = True
            elif form_remote != cve.remote:
                not_merged.append(form.remote)
        form.remote.data = cve.remote.name

        # try to merge description
        if form.description.data:
            if not cve.description:
                cve.description = form.description.data
                merged = True
            elif form.description.data != cve.description:
                not_merged.append(form.description)
        form.description.data = cve.description

        # try to merge references
        references = cve.reference.splitlines() if cve.reference else []
        old_references = references.copy()
        form_references = form.reference.data.splitlines() if form.reference.data else []
        for reference in form_references:
            if reference not in references:
                references.append(reference)
                merged = True
        if old_references != references:
            cve.reference = '\n'.join(references)
        form.reference.data = cve.reference

        # try to merge notes
        if form.notes.data:
            if not cve.notes:
                cve.notes = form.notes.data
                merged = True
            elif form.notes.data != cve.notes:
                not_merged.append(form.notes)
        form.notes.data = cve.notes

        # if something got merged, commit and flash
        if merged:
            db.session.commit()
            flash(CVE_MERGED.format(cve.id))

        # warn if something failed to be merged
        if not_merged:
            for field in not_merged:
                field.errors.append(ERROR_UNMERGEABLE)

            not_merged_labels = [field.label.text for field in not_merged]
            flash(CVE_MERGED_PARTIALLY.format(cve.id, ', '.join(not_merged_labels)), 'warning')
            return render_template('form/cve.html',
                                   title='Edit {}'.format(cve),
                                   form=form,
                                   CVE=CVE,
                                   action='{}/edit'.format(cve.id))

        return redirect('/{}'.format(cve.id))

    cve = CVE()
    cve.id = form.cve.data
    cve.issue_type = form.issue_type.data
    cve.description = form.description.data
    cve.severity = Severity.fromstring(form.severity.data)
    cve.remote = Remote.fromstring(form.remote.data)
    cve.reference = form.reference.data
    cve.notes = form.notes.data
    db.session.add(cve)
    db.session.commit()
    flash('Added {}'.format(cve.id))
    return redirect('/{}'.format(cve.id))


@tracker.route('/avg/add', methods=['GET', 'POST'])
@reporter_required
def add_group():
    form = GroupForm()
    if not form.validate_on_submit():
        return render_template('form/group.html',
                               title='Add AVG',
                               form=form,
                               CVEGroup=CVEGroup)

    issue_ids = multiline_to_list(form.cve.data)
    issue_ids = set(filter(lambda s: s.startswith('CVE-'), issue_ids))

    existing_issues = CVE.query.filter(CVE.id.in_(issue_ids)).all()
    existing_issue_ids = [issue.id for issue in existing_issues]

    pkgnames = multiline_to_list(form.pkgnames.data)

    # check if a package with a CVE clashes with an existing group
    if not form.force_submit.data:
        same_group = (db.session.query(CVEGroup, CVE, CVEGroupPackage)
                      .join(CVEGroupEntry, CVEGroup.issues)
                      .join(CVE, CVEGroupEntry.cve)
                      .join(CVEGroupPackage, CVEGroup.packages)
                      .filter(CVEGroupPackage.pkgname.in_(pkgnames)))
        if issue_ids:
            same_group = same_group.filter(CVE.id.in_(issue_ids))
        same_group = same_group.all()
        if same_group:
            for group, cve, package in same_group:
                flash(ERROR_GROUP_WITH_ISSUE_EXISTS
                      .format(group.id, cve.id, package.pkgname), 'warning')
            return render_template('form/group.html',
                                   title='Add AVG',
                                   form=form,
                                   CVEGroup=CVEGroup,
                                   show_force=True)

    for cve_id in list(filter(lambda issue: issue not in existing_issue_ids, issue_ids)):
        cve = db.create(CVE, id=cve_id)
        existing_issues.append(cve)
        flash('Added {}'.format(cve.id))

    fixed = form.fixed.data
    affected = Affected.fromstring(form.status.data)
    status = affected_to_status(affected, pkgnames[0], fixed)
    severity = highest_severity([issue.severity for issue in existing_issues])
    advisory_qualified = form.advisory_qualified.data and status is not Status.not_affected

    group = db.create(CVEGroup,
                      affected=form.affected.data,
                      status=status,
                      fixed=fixed,
                      bug_ticket=form.bug_ticket.data,
                      reference=form.reference.data,
                      notes=form.notes.data,
                      severity=severity,
                      advisory_qualified=advisory_qualified)

    for cve in existing_issues:
        db.create(CVEGroupEntry, group=group, cve=cve)

    for pkgname in pkgnames:
        db.get_or_create(CVEGroupPackage, pkgname=pkgname, group=group)
        flash('Added {}'.format(pkgname))

    db.session.commit()
    flash('Added {}'.format(group.name))

    missing_variants(pkgnames, group)

    return redirect('/{}'.format(group.name))


def missing_variants(pkgnames, group, variants=['lib32']):
    testpkgs = []
    for pkgname in pkgnames:
        for variant in variants:
            if variant in pkgname:
                pkg = pkgname.replace(f'{variant}-', '')
                if pkg not in pkgnames:
                    testpkgs.append(pkg)
            else:
                pkg = f'{variant}-{pkgname}'
                if pkg not in pkgnames:
                    testpkgs.append(pkg)

    package_data = Package.query.filter(Package.name.in_(testpkgs)).all()
    for pkg in package_data:
        if pkg not in group.packages:
            flash('Missing AVG for {}'.format(pkg.name))
