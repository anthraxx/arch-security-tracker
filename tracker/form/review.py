from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms.validators import Length
from wtforms.validators import Optional

from tracker.model.review import Review

from .base import BaseForm

class ReviewForm(BaseForm):
    note = TextAreaField(u'Notes', validators=[Optional(), Length(max=Review.NOTE_LENGTH)])
    approve = SubmitField(u'approve')
    revoke = SubmitField(u'disapprove')

    def __init__(self, edit=False):
        super().__init__()

    def validate(self):
        rv = BaseForm.validate(self)
        if not rv:
            return False

        if self.revoke.data and not self.note.data:
            return False

        return True
