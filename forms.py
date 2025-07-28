from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from wtforms.validators import InputRequired, Length

class UserEnvironmentForm(FlaskForm):
    tool_type = StringField("Tool Type", validators=[InputRequired(), Length(max=64)])
    tool_name = StringField("Tool Name", validators=[InputRequired(), Length(max=128)])
    details = TextAreaField("Details", validators=[Length(max=1000)])