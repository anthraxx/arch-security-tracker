from .base import BaseForm
from wtforms import StringField, SelectField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Optional, Regexp, Length
from app.model.cvegroup import pkgver_regex, CVEGroup
from app.model.enum import Affected
from app.form.validators import ValidPackageNames, SamePackageVersions, ValidIssues, ValidURLs
from pyalpm import vercmp


class GroupForm(BaseForm):
    cve = TextAreaField(u'CVE', validators=[DataRequired(), ValidIssues()])
    # TODO: check if the pkgnames are all belonging to the same pkgbase instead of checking for the versions
    pkgnames = TextAreaField(u'Package', validators=[DataRequired(), ValidPackageNames(), SamePackageVersions()])
    description = TextAreaField(u'Description', validators=[Optional()])
    affected = StringField(u'Affected', validators=[DataRequired(), Regexp(pkgver_regex)])
    fixed = StringField(u'Fixed', validators=[Optional(), Regexp(pkgver_regex)])
    status = SelectField(u'Status', choices=[(e.name, e.label) for e in [*Affected]], validators=[DataRequired()])
    bug_ticket = StringField('Bug ticket', validators=[Optional(), Regexp(r'^\d+$')])
    reference = TextAreaField(u'References', validators=[Optional(), Length(max=CVEGroup.REFERENCES_LENGTH), ValidURLs()])
    notes = TextAreaField(u'Notes', validators=[Optional(), Length(max=CVEGroup.NOTES_LENGTH)])
    advisory_qualified = BooleanField(u'Advisory qualified', default=True, validators=[Optional()])
    submit = SubmitField(u'submit')

    def validate(self):
        rv = BaseForm.validate(self)
        if not rv:
            return False
        if self.fixed.data and 0 <= vercmp(self.affected.data, self.fixed.data):
            self.fixed.errors.append('Version must be newer.')
            return False
        return True
