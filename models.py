from extensions import db
from datetime import datetime
import secrets
import json

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    invitations = db.relationship('Invitation', backref='user', lazy=True, cascade='all, delete-orphan')

class OTP(db.Model):
    __tablename__ = 'otps'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    purpose = db.Column(db.String(20), nullable=False, default='verification')
    is_used = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class EventType(db.Model):
    __tablename__ = 'event_types'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    display_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    icon = db.Column(db.String(50))
    color = db.Column(db.String(7))
    is_active = db.Column(db.Boolean, default=True)
    sort_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Template(db.Model):
    __tablename__ = 'templates'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    event_type = db.Column(db.String(50), nullable=False)
    religious_type = db.Column(db.String(50), nullable=False)
    style = db.Column(db.String(50))
    color_scheme = db.Column(db.String(50))
    preview_image = db.Column(db.String(255))
    font_family = db.Column(db.String(100))
    emoji_theme = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    usage_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Invitation(db.Model):
    __tablename__ = 'invitations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    event_type = db.Column(db.String(50), nullable=False)
    template_name = db.Column(db.String(100))
    event_date = db.Column(db.DateTime)
    event_style = db.Column(db.String(50))

    # Event-specific fields
    bride_name = db.Column(db.String(100))
    groom_name = db.Column(db.String(100))
    muhurtham_time = db.Column(db.String(50))
    reception_time = db.Column(db.String(50))

    birthday_person = db.Column(db.String(100))
    age = db.Column(db.String(10))
    start_time = db.Column(db.String(50))
    dinner_time = db.Column(db.String(50))

    mother_name = db.Column(db.String(100))
    father_name = db.Column(db.String(100))
    babyshower_start_time = db.Column(db.String(50))
    babyshower_end_time = db.Column(db.String(50))

    graduate_name = db.Column(db.String(100))
    degree = db.Column(db.String(100))
    school = db.Column(db.String(100))
    major = db.Column(db.String(100))

    couple_names = db.Column(db.String(100))
    marriage_years = db.Column(db.String(20))
    anniversary_dinner_time = db.Column(db.String(50))
    party_time = db.Column(db.String(50))

    honoree_name = db.Column(db.String(100))
    position = db.Column(db.String(100))
    company = db.Column(db.String(100))
    start_year = db.Column(db.String(10))

    # Contact information
    host_name = db.Column(db.String(100))
    contact_phone = db.Column(db.String(20))
    contact_email = db.Column(db.String(120))
    venue_address = db.Column(db.Text)

    # Image fields
    main_image = db.Column(db.String(255))
    bride_image = db.Column(db.String(255))
    groom_image = db.Column(db.String(255))
    birthday_image = db.Column(db.String(255))
    couple_image = db.Column(db.String(255))
    graduate_image = db.Column(db.String(255))
    honoree_image = db.Column(db.String(255))
    gallery_images = db.Column(db.Text)  # JSON string of image filenames

    share_url = db.Column(db.String(100), unique=True, nullable=False)
    view_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)



def init_sample_data():
    """Initialize the database with sample templates and event types"""

    # Sample Event Types
    event_types = [
        {
            'name': 'wedding',
            'display_name': 'Wedding',
            'description': 'Celebrate the union of two hearts',
            'icon': 'fas fa-heart',
            'color': '#e91e63',
            'sort_order': 1
        },
        {
            'name': 'birthday',
            'display_name': 'Birthday Party',
            'description': 'Celebrate another year of life',
            'icon': 'fas fa-birthday-cake',
            'color': '#ff9800',
            'sort_order': 2
        },
        {
            'name': 'anniversary',
            'display_name': 'Anniversary',
            'description': 'Celebrate years of togetherness',
            'icon': 'fas fa-heart',
            'color': '#9c27b0',
            'sort_order': 3
        },
        {
            'name': 'babyshower',
            'display_name': 'Baby Shower',
            'description': 'Welcome the new arrival',
            'icon': 'fas fa-baby',
            'color': '#2196f3',
            'sort_order': 4
        },
        {
            'name': 'graduation',
            'display_name': 'Graduation Party',
            'description': 'Celebrate academic achievements',
            'icon': 'fas fa-graduation-cap',
            'color': '#4caf50',
            'sort_order': 5
        },
        {
            'name': 'retirement',
            'display_name': 'Retirement Party',
            'description': 'Honor years of dedicated service',
            'icon': 'fas fa-chair',
            'color': '#795548',
            'sort_order': 6
        }
    ]

    for event_type_data in event_types:
        if not EventType.query.filter_by(name=event_type_data['name']).first():
            event_type = EventType(**event_type_data)
            db.session.add(event_type)

    # Sample Templates with Religious Types
    templates = [
        # Hindu Wedding Templates
        {
            'name': 'Sacred Hindu Ceremony',
            'description': 'Traditional Hindu wedding with sacred symbols',
            'event_type': 'wedding',
            'religious_type': 'hindu',
            'style': 'traditional',
            'color_scheme': 'gold',
            'font_family': 'Georgia, serif',
            'emoji_theme': 'Om Wedding Flowers',
            'preview_image': 'https://via.placeholder.com/300x400/FF6B35/FFFFFF?text=Hindu+Wedding'
        },
        {
            'name': 'Royal Hindu Wedding',
            'description': 'Elegant Hindu wedding with royal touch',
            'event_type': 'wedding',
            'religious_type': 'hindu',
            'style': 'royal',
            'color_scheme': 'red',
            'font_family': 'Playfair Display, serif',
            'emoji_theme': 'Crown Rose Fire',
            'preview_image': 'https://via.placeholder.com/300x400/DC143C/FFFFFF?text=Royal+Hindu'
        },
        # Muslim Wedding Templates
        {
            'name': 'Islamic Nikah',
            'description': 'Beautiful Islamic wedding invitation',
            'event_type': 'wedding',
            'religious_type': 'muslim',
            'style': 'traditional',
            'color_scheme': 'green',
            'font_family': 'Amiri, serif',
            'emoji_theme': 'Crescent Mosque Heart',
            'preview_image': 'https://via.placeholder.com/300x400/228B22/FFFFFF?text=Islamic+Nikah'
        },
        {
            'name': 'Elegant Muslim Wedding',
            'description': 'Modern Islamic wedding design',
            'event_type': 'wedding',
            'religious_type': 'muslim',
            'style': 'modern',
            'color_scheme': 'teal',
            'font_family': 'Lora, serif',
            'emoji_theme': 'Moon Stars Ring',
            'preview_image': 'https://via.placeholder.com/300x400/008080/FFFFFF?text=Muslim+Wedding'
        },
        # Christian Wedding Templates
        {
            'name': 'Christian Ceremony',
            'description': 'Sacred Christian wedding invitation',
            'event_type': 'wedding',
            'religious_type': 'christian',
            'style': 'classic',
            'color_scheme': 'white',
            'font_family': 'Times New Roman, serif',
            'emoji_theme': 'Cross Church Wedding',
            'preview_image': 'https://via.placeholder.com/300x400/FFFFFF/000000?text=Christian+Wedding'
        },
        {
            'name': 'Modern Christian Wedding',
            'description': 'Contemporary Christian wedding design',
            'event_type': 'wedding',
            'religious_type': 'christian',
            'style': 'modern',
            'color_scheme': 'blue',
            'font_family': 'Montserrat, sans-serif',
            'emoji_theme': 'Wedding Dove Blue',
            'preview_image': 'https://via.placeholder.com/300x400/4169E1/FFFFFF?text=Modern+Christian'
        },
        {
            'name': 'Elegant Wedding',
            'description': 'Beautiful elegant wedding invitation inspired by HarryNancy design',
            'event_type': 'wedding',
            'religious_type': 'general',
            'style': 'elegant',
            'color_scheme': 'gold',
            'font_family': 'Playfair Display, serif',
            'emoji_theme': 'Wedding Ring Heart',
            'preview_image': 'https://via.placeholder.com/300x400/FFD700/000000?text=Elegant+Wedding'
        },
        {
            'name': 'Traditional Hindu Wedding',
            'description': 'Traditional Hindu wedding with sacred symbols and cultural elements',
            'event_type': 'wedding',
            'religious_type': 'hindu',
            'style': 'traditional',
            'color_scheme': 'orange',
            'font_family': 'Playfair Display, serif',
            'emoji_theme': 'Om Wedding Flowers',
            'preview_image': 'https://via.placeholder.com/300x400/FF6B35/FFFFFF?text=Hindu+Wedding'
        },
        {
            'name': 'Elegant Muslim Wedding',
            'description': 'Beautiful Islamic wedding with elegant design and cultural elements',
            'event_type': 'wedding',
            'religious_type': 'muslim',
            'style': 'elegant',
            'color_scheme': 'green',
            'font_family': 'Playfair Display, serif',
            'emoji_theme': 'Crescent Mosque Heart',
            'preview_image': 'https://via.placeholder.com/300x400/228B22/FFFFFF?text=Muslim+Wedding'
        },
        # Hindu Birthday Templates
        {
            'name': 'Traditional Hindu Birthday',
            'description': 'Traditional Hindu birthday celebration',
            'event_type': 'birthday',
            'religious_type': 'hindu',
            'style': 'traditional',
            'color_scheme': 'orange',
            'font_family': 'Noto Sans Devanagari, sans-serif',
            'emoji_theme': 'Cake Lamp Flowers',
            'preview_image': 'https://via.placeholder.com/300x400/FF8C00/FFFFFF?text=Hindu+Birthday'
        },
        # Muslim Birthday Templates
        {
            'name': 'Islamic Birthday',
            'description': 'Islamic birthday celebration invitation',
            'event_type': 'birthday',
            'religious_type': 'muslim',
            'style': 'traditional',
            'color_scheme': 'green',
            'font_family': 'Amiri, serif',
            'emoji_theme': 'Cake Crescent Moon',
            'preview_image': 'https://via.placeholder.com/300x400/32CD32/FFFFFF?text=Islamic+Birthday'
        },
        # Christian Birthday Templates
        {
            'name': 'Christian Birthday',
            'description': 'Christian birthday celebration invitation',
            'event_type': 'birthday',
            'religious_type': 'christian',
            'style': 'classic',
            'color_scheme': 'blue',
            'font_family': 'Georgia, serif',
            'emoji_theme': 'Cake Cross Party',
            'preview_image': 'https://via.placeholder.com/300x400/1E90FF/FFFFFF?text=Christian+Birthday'
        },
        # General Birthday Templates
        {
            'name': 'Fun & Colorful',
            'description': 'Vibrant and playful birthday invitation',
            'event_type': 'birthday',
            'religious_type': 'general',
            'style': 'fun',
            'color_scheme': 'rainbow',
            'font_family': 'Comic Sans MS, cursive',
            'emoji_theme': 'Cake Party Balloons',
            'preview_image': 'https://via.placeholder.com/300x400/FF69B4/FFFFFF?text=Fun+Birthday'
        },
        {
            'name': 'Fun & Colorful Birthday',
            'description': 'Vibrant and playful birthday invitation with floating balloons',
            'event_type': 'birthday',
            'religious_type': 'general',
            'style': 'fun',
            'color_scheme': 'pink',
            'font_family': 'Fredoka One, cursive',
            'emoji_theme': 'Cake Party Balloons',
            'preview_image': 'https://via.placeholder.com/300x400/FF69B4/FFFFFF?text=Fun+Birthday'
        },
        # Other Templates
        {
            'name': 'Golden Anniversary',
            'description': 'Perfect for milestone anniversaries',
            'event_type': 'anniversary',
            'religious_type': 'general',
            'style': 'elegant',
            'color_scheme': 'gold',
            'preview_image': 'https://via.placeholder.com/300x400/FFD700/000000?text=Golden+Anniversary'
        },
        {
            'name': 'Golden Elegant Anniversary',
            'description': 'Elegant anniversary celebration with timeline and golden design',
            'event_type': 'anniversary',
            'religious_type': 'general',
            'style': 'elegant',
            'color_scheme': 'gold',
            'font_family': 'Playfair Display, serif',
            'emoji_theme': 'Couple Ring Diamond',
            'preview_image': 'https://via.placeholder.com/300x400/FFD700/000000?text=Golden+Anniversary'
        },
        {
            'name': 'Sweet Baby Shower',
            'description': 'Adorable baby shower invitation',
            'event_type': 'babyshower',
            'religious_type': 'general',
            'style': 'cute',
            'color_scheme': 'pink',
            'preview_image': 'https://via.placeholder.com/300x400/FFB6C1/000000?text=Sweet+Baby+Shower'
        },
        {
            'name': 'Sweet Pink Baby Shower',
            'description': 'Adorable baby shower invitation with floating baby elements',
            'event_type': 'babyshower',
            'religious_type': 'general',
            'style': 'cute',
            'color_scheme': 'pink',
            'font_family': 'Dancing Script, cursive',
            'emoji_theme': 'Baby Bottle Teddy',
            'preview_image': 'https://via.placeholder.com/300x400/FFB6C1/000000?text=Sweet+Baby+Shower'
        },
        {
            'name': 'Graduation Success',
            'description': 'Celebrate academic achievements',
            'event_type': 'graduation',
            'religious_type': 'general',
            'style': 'modern',
            'color_scheme': 'blue',
            'preview_image': 'https://via.placeholder.com/300x400/4169E1/FFFFFF?text=Graduation+Success'
        },
        {
            'name': 'Modern Graduation Success',
            'description': 'Modern graduation celebration with academic achievements',
            'event_type': 'graduation',
            'religious_type': 'general',
            'style': 'modern',
            'color_scheme': 'blue',
            'font_family': 'Playfair Display, serif',
            'emoji_theme': 'GraduationCap Books Trophy',
            'preview_image': 'https://via.placeholder.com/300x400/4169E1/FFFFFF?text=Graduation+Success'
        },
        {
            'name': 'Retirement Celebration',
            'description': 'Honor years of dedicated service',
            'event_type': 'retirement',
            'religious_type': 'general',
            'style': 'classic',
            'color_scheme': 'gold',
            'preview_image': 'https://via.placeholder.com/300x400/FFD700/000000?text=Retirement+Celebration'
        },
        {
            'name': 'Golden Classic Retirement',
            'description': 'Classic retirement celebration with career timeline',
            'event_type': 'retirement',
            'religious_type': 'general',
            'style': 'classic',
            'color_scheme': 'gold',
            'font_family': 'Playfair Display, serif',
            'emoji_theme': 'Crown Trophy Star',
            'preview_image': 'https://via.placeholder.com/300x400/FFD700/000000?text=Retirement+Celebration'
        }
    ]

    for template_data in templates:
        if not Template.query.filter_by(name=template_data['name']).first():
            template = Template(**template_data)
            db.session.add(template)

    db.session.commit()
    print("Sample data initialized successfully!")