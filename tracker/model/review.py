from datetime import datetime

from tracker import db


class Review(db.Model):

    NOTE_LENGTH = 4096

    __tablename__ = 'review'
    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    user = db.relationship('User') 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    advisory = db.relationship('Advisory')
    advisory_id = db.Column(db.Integer, db.ForeignKey('advisory.id'))
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    approved = db.Column(db.Boolean, default=False)
    note = db.Column(db.String(NOTE_LENGTH))
