from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, DateField, TimeField, FileField, SelectField
from wtforms.validators import DataRequired, Optional

class InvitationForm(FlaskForm):
    """Form for creating invitations"""
    title = StringField('Title', validators=[DataRequired()])
    event_date = DateField('Event Date', validators=[DataRequired()])
    event_time = TimeField('Event Time', validators=[Optional()])
    description = TextAreaField('Description', validators=[Optional()])
    venue = StringField('Venue', validators=[Optional()])
    message = TextAreaField('Message', validators=[Optional()])

