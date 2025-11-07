from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, DateField, TimeField, SelectField
from wtforms.validators import DataRequired, Optional

class InvitationForm(FlaskForm):
    """Form for creating invitations"""
    # Basic fields
    title = StringField('Title', validators=[DataRequired()])
    event_date = DateField('Event Date', validators=[DataRequired()])
    event_time = TimeField('Event Time', validators=[Optional()])
    venue = StringField('Venue', validators=[Optional()])
    host_name = StringField('Host Name', validators=[Optional()])
    message = TextAreaField('Message', validators=[Optional()])
    description = TextAreaField('Description', validators=[Optional()])
    
    # Wedding-specific fields
    bride_name = StringField('Bride Name', validators=[Optional()])
    groom_name = StringField('Groom Name', validators=[Optional()])
    
    # Image upload fields
    main_image = FileField('Main Image', validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    bride_image = FileField('Bride Image', validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    groom_image = FileField('Groom Image', validators=[Optional(), FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')])
    
    # RSVP fields
    rsvp_contact = StringField('RSVP Contact', validators=[Optional()])
    rsvp_email = StringField('RSVP Email', validators=[Optional()])
    
    # Customization fields
    language = SelectField('Language', choices=[('en', 'English'), ('es', 'Spanish'), ('fr', 'French'), ('de', 'German'), ('it', 'Italian'), ('pt', 'Portuguese')], validators=[Optional()])
    font_style = SelectField('Font Style', choices=[('elegant', 'Elegant'), ('modern', 'Modern'), ('classic', 'Classic'), ('playful', 'Playful')], validators=[Optional()])

