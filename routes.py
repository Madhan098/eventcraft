from flask import render_template, request, jsonify, session, redirect, url_for, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from extensions import db
from models import User, OTP, Invitation, Template, EventType
from utils import send_otp_email, generate_otp
from datetime import datetime, timedelta
import json
import random
import string
import os

# Helper function to check authentication (moved outside register_routes)
def is_authenticated():
    return 'user_id' in session

def generate_unique_share_url():
    """Generate a unique share URL for invitations"""
    while True:
        # Generate a random 8-character string
        share_url = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        
        # Check if it already exists
        if not Invitation.query.filter_by(share_url=share_url).first():
            return share_url

def register_routes(app):
    # Custom Jinja2 filter for safe JSON parsing
    @app.template_filter('safe_from_json')
    def safe_from_json(value):
        try:
            if value and value.strip() and value != 'null':
                parsed = json.loads(value)
                # Ensure it's a list and filter out empty strings
                if isinstance(parsed, list):
                    return [item for item in parsed if item and str(item).strip()]
                return []
            return []
        except (json.JSONDecodeError, AttributeError, TypeError):
            return []

    @app.route('/')
    def index():
        if is_authenticated():
            return redirect(url_for('dashboard'))
        return render_template('index.html')

    @app.route('/auth')
    def auth():
        if is_authenticated():
            return redirect(url_for('dashboard'))
        return render_template('auth/login.html')

    @app.route('/register', methods=['POST'])
    def register():
        try:
            data = request.form
            
            # Check if user already exists
            if User.query.filter_by(email=data['email']).first():
                flash('Email already registered', 'error')
                return redirect(url_for('auth'))
            
            if User.query.filter_by(mobile=data['mobile']).first():
                flash('Mobile number already registered', 'error')
                return redirect(url_for('auth'))
            
            # Create new user
            user = User(
                name=data['name'],
                mobile=data['mobile'],
                email=data['email'],
                password_hash=generate_password_hash(data['password'])
            )
            db.session.add(user)
            db.session.commit()
            
            # Generate and send OTP
            otp_code = generate_otp()
            otp = OTP(
                email=data['email'],
                otp_code=otp_code,
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(otp)
            db.session.commit()
            
            # Send OTP email
            send_otp_email(data['email'], otp_code, purpose='verification')
            
            session['temp_email'] = data['email']
            
            flash('OTP sent to your email. Please check your inbox.', 'success')
            return redirect(url_for('verify_otp'))
            
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'error')
            return redirect(url_for('auth'))

    @app.route('/login', methods=['POST'])
    def login():
        try:
            data = request.form
            
            user = User.query.filter_by(email=data['email']).first()
            
            if user and check_password_hash(user.password_hash, data['password']):
                if not user.is_verified:
                    flash('Please verify your email first', 'error')
                    return redirect(url_for('auth'))
                
                session['user_id'] = user.id
                session['user_name'] = user.name
                session['user_email'] = user.email
                session.permanent = True
                
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
                return redirect(url_for('auth'))
                
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('Login failed', 'error')
            return redirect(url_for('auth'))

    @app.route('/verify-otp')
    def verify_otp():
        if 'temp_email' not in session:
            return redirect(url_for('auth'))
        return render_template('auth/verify_otp.html')

    @app.route('/verify-otp', methods=['POST'])
    def verify_otp_post():
        try:
            otp_code = request.form['otp']
            email = session['temp_email']
            
            # Find the OTP
            otp = OTP.query.filter_by(
                email=email, 
                otp_code=otp_code, 
                is_used=False,
                purpose='verification'
            ).first()
            
            if otp and otp.expires_at > datetime.utcnow():
                # Mark OTP as used
                otp.is_used = True
                
                # Verify the user
                user = User.query.filter_by(email=email).first()
                if user:
                    user.is_verified = True
                    db.session.commit()
                    
                    # Clear temp session
                    session.pop('temp_email', None)
                    
                    flash('Email verified successfully! Please login.', 'success')
                    return redirect(url_for('auth'))
                else:
                    flash('User not found', 'error')
                    return redirect(url_for('auth'))
            else:
                flash('Invalid or expired OTP', 'error')
                return redirect(url_for('verify_otp'))
                
        except Exception as e:
            app.logger.error(f"OTP verification error: {str(e)}")
            flash('Verification failed. Please try again.', 'error')
            return redirect(url_for('verify_otp'))

    @app.route('/dashboard')
    def dashboard():
        if not is_authenticated():
            flash('Please login to continue', 'error')
            return redirect(url_for('auth'))
        
        user_id = session['user_id']
        user_name = session.get('user_name', 'User')
        user_email = session.get('user_email', '')
        
        invitations = Invitation.query.filter_by(user_id=user_id).order_by(Invitation.created_at.desc()).all()
        
        return render_template('dashboard/dashboard.html', invitations=invitations)

    @app.route('/logout')
    def logout():
        session.clear()
        flash('Logged out successfully', 'success')
        return redirect(url_for('index'))

    @app.route('/templates')
    def templates():
        # Templates page is public - no login required
        event_types = EventType.query.all()
        return render_template('templates.html', event_types=event_types)

    @app.route('/create-invitation')
    def create_invitation():
        if not is_authenticated():
            flash('Please login to create an invitation', 'error')
            return redirect(url_for('auth'))
        
        # Get template parameter if coming from templates page
        selected_template = request.args.get('template')
        
        # Get current user information
        try:
            current_user = User.query.get(session['user_id'])
        except Exception as e:
            app.logger.error(f"Error getting user: {str(e)}")
            flash('Error retrieving user information', 'error')
            return redirect(url_for('auth'))
        
        event_types = EventType.query.all()
        return render_template('invitation/create.html', 
                             event_types=event_types, 
                             selected_template=selected_template,
                             current_user=current_user)

    @app.route('/create-invitation', methods=['POST'])
    def create_invitation_post():
        if not is_authenticated():
            flash('Please login to create an invitation', 'error')
            return redirect(url_for('auth'))
        
        try:
            data = request.form
            selected_template = data.get('selectedTemplate', '')
            
            # Create new invitation
            invitation = Invitation(
                user_id=session['user_id'],
                title=data.get('eventTitle', ''),
                description=data.get('eventDescription', ''),
                event_type=selected_template.split('_')[0] if selected_template else 'general',
                template_name=selected_template,
                event_date=datetime.strptime(data.get('eventDate', ''), '%Y-%m-%d') if data.get('eventDate') else None,
                event_style=data.get('eventStyle', ''),
                
                # Event-specific fields
                bride_name=data.get('brideName', ''),
                groom_name=data.get('groomName', ''),
                muhurtham_time=data.get('muhurthamTime', ''),
                reception_time=data.get('receptionTime', ''),
                
                birthday_person=data.get('birthdayPerson', ''),
                age=data.get('age', ''),
                start_time=data.get('startTime', ''),
                dinner_time=data.get('dinnerTime', ''),
                
                mother_name=data.get('motherName', ''),
                father_name=data.get('fatherName', ''),
                babyshower_start_time=data.get('babyshowerStartTime', ''),
                babyshower_end_time=data.get('babyshowerEndTime', ''),
                
                graduate_name=data.get('graduateName', ''),
                degree=data.get('degree', ''),
                school=data.get('school', ''),
                major=data.get('major', ''),
                
                couple_names=data.get('coupleNames', ''),
                marriage_years=data.get('marriageYears', ''),
                anniversary_dinner_time=data.get('anniversaryDinnerTime', ''),
                party_time=data.get('partyTime', ''),
                
                honoree_name=data.get('honoreeName', ''),
                position=data.get('position', ''),
                company=data.get('company', ''),
                start_year=data.get('startYear', ''),
                
                # Contact information
                host_name=data.get('hostName', ''),
                contact_phone=data.get('contactPhone', ''),
                contact_email=data.get('contactEmail', ''),
                venue_address=data.get('venueAddress', ''),
                
                # Generate unique share URL
                share_url=generate_unique_share_url(),
                is_active=True,
                view_count=0
            )
            
            db.session.add(invitation)
            db.session.commit()
            
            flash('Invitation created successfully!', 'success')
            return redirect(url_for('view_invitation_final', share_url=invitation.share_url))
            
        except Exception as e:
            app.logger.error(f"Error creating invitation: {str(e)}")
            db.session.rollback()
            flash('Error creating invitation. Please try again.', 'error')
            return redirect(url_for('create_invitation'))

    @app.route('/uploads/<filename>')
    def uploaded_file(filename):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

    @app.route('/static/uploads/<filename>')
    def static_uploaded_file(filename):
        return send_from_directory('uploads', filename)

    @app.route('/test')
    def test():
        return 'Flask app is working!'

    @app.route('/test-template')
    def test_template():
        return render_template('test_simple.html')

    @app.route('/test-dashboard')
    def test_dashboard():
        return 'Dashboard route is working!'

    @app.route('/about')
    def about():
        return render_template('about.html')

    @app.route('/contact', methods=['GET', 'POST'])
    def contact():
        if request.method == 'POST':
            # Handle contact form submission
            flash('Thank you for your message! We will get back to you soon.', 'success')
            return redirect(url_for('contact'))
        return render_template('contact.html')

    @app.route('/privacy')
    def privacy():
        return render_template('privacy.html')

    @app.route('/terms')
    def terms():
        return render_template('terms.html')

    @app.route('/forgot-password', methods=['POST'])
    def forgot_password():
        try:
            data = request.get_json() if request.is_json else request.form
            email = data.get('email', '').strip()
            
            if not email:
                return jsonify({'success': False, 'message': 'Email is required'})
            
            # Check if user exists
            user = User.query.filter_by(email=email).first()
            if not user:
                return jsonify({'success': False, 'message': 'User not found with this email'})
            
            # Generate and send OTP
            otp_code = generate_otp()
            otp = OTP(
                email=email,
                otp_code=otp_code,
                purpose='password_reset',
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(otp)
            db.session.commit()
            
            # Send OTP email
            send_otp_email(email, otp_code, purpose='password_reset')
            
            return jsonify({'success': True, 'message': 'OTP sent to your email'})
            
        except Exception as e:
            app.logger.error(f"Forgot password error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'Failed to send OTP. Please try again.'})

    @app.route('/verify-reset-otp', methods=['POST'])
    def verify_reset_otp():
        try:
            data = request.get_json() if request.is_json else request.form
            email = data.get('email', '').strip()
            otp_code = data.get('otp', '').strip()
            
            if not email or not otp_code:
                return jsonify({'success': False, 'message': 'Email and OTP are required'})
            
            # Find valid OTP
            otp = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                purpose='password_reset',
                is_used=False
            ).first()
            
            if not otp:
                return jsonify({'success': False, 'message': 'Invalid OTP'})
            
            if otp.expires_at < datetime.utcnow():
                return jsonify({'success': False, 'message': 'OTP has expired. Please request a new one.'})
            
            # Mark OTP as used
            otp.is_used = True
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'OTP verified successfully'})
            
        except Exception as e:
            app.logger.error(f"Verify reset OTP error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'An error occurred. Please try again.'})

    @app.route('/reset-password', methods=['POST'])
    def reset_password():
        try:
            data = request.get_json() if request.is_json else request.form
            email = data.get('email', '').strip()
            otp_code = data.get('otp', '').strip()
            password = data.get('password', '').strip()
            confirm_password = data.get('confirm_password', '').strip()
            
            if not email or not otp_code or not password or not confirm_password:
                return jsonify({'success': False, 'message': 'All fields are required'})
            
            if password != confirm_password:
                return jsonify({'success': False, 'message': 'Passwords do not match'})
            
            if len(password) < 6:
                return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
            
            # Verify OTP was used (additional security check)
            otp = OTP.query.filter_by(
                email=email,
                otp_code=otp_code,
                purpose='password_reset',
                is_used=True
            ).first()
            
            if not otp:
                return jsonify({'success': False, 'message': 'Invalid or expired OTP. Please request a new one.'})
            
            # Update user password
            user = User.query.filter_by(email=email).first()
            if not user:
                return jsonify({'success': False, 'message': 'User not found'})
            
            user.password_hash = generate_password_hash(password)
            user.updated_at = datetime.utcnow()
            
            # Remove the used OTP
            db.session.delete(otp)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Password reset successfully'})
            
        except Exception as e:
            app.logger.error(f"Reset password error: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'message': 'An error occurred. Please try again.'})

    @app.route('/view-invitation-manage/<share_url>')
    def view_invitation_manage(share_url):
        if not is_authenticated():
            flash('Please login to continue', 'error')
            return redirect(url_for('auth'))
        
        invitation = Invitation.query.filter_by(share_url=share_url).first()
        if not invitation or invitation.user_id != session['user_id']:
            flash('Invitation not found or access denied', 'error')
            return redirect(url_for('dashboard'))
        
        return render_template('invitation/manage.html', invitation=invitation)

    @app.route('/view-invitation-final/<share_url>')
    def view_invitation_final(share_url):
        """View the final invitation as guests would see it"""
        invitation = Invitation.query.filter_by(share_url=share_url).first()
        if not invitation:
            flash('Invitation not found', 'error')
            return redirect(url_for('dashboard'))
        
        # Increment view count if user is not the owner
        if not is_authenticated() or invitation.user_id != session.get('user_id'):
            invitation.view_count += 1
            db.session.commit()
        
        # Prepare event_data in the format the templates expect
        event_data = {
            'eventTitle': invitation.title or 'Event Invitation',
            'eventDescription': invitation.description or '',
            'eventDate': invitation.event_date.strftime('%B %d, %Y') if invitation.event_date else '',
            'eventTime': invitation.muhurtham_time or invitation.start_time or invitation.anniversary_dinner_time or invitation.babyshower_start_time or '',
            'venue': invitation.venue_address or '',
            'address': invitation.venue_address or '',
            'description': invitation.description or '',
            'religiousType': invitation.event_style or 'general',
            'familyName': invitation.title or 'Event Invitation',
            
            # Wedding specific
            'brideName': invitation.bride_name or '',
            'groomName': invitation.groom_name or '',
            'bridePhoto': None,  # We don't have photo fields in current model
            'groomPhoto': None,
            'brideDescription': 'Beautiful Bride',
            'groomDescription': 'Handsome Groom',
            
            # Birthday specific
            'birthdayPerson': invitation.birthday_person or '',
            'age': invitation.age or '',
            'startTime': invitation.start_time or '',
            'dinnerTime': invitation.dinner_time or '',
            
            # Baby shower specific
            'motherName': invitation.mother_name or '',
            'fatherName': invitation.father_name or '',
            'startTime': invitation.babyshower_start_time or '',
            'endTime': invitation.babyshower_end_time or '',
            'babyGender': '👶',
            'gender': 'Baby',
            'babyName': 'Little Angel',
            'dueDate': 'Coming Soon',
            
            # Graduation specific
            'graduateName': invitation.graduate_name or '',
            'degree': invitation.degree or '',
            'school': invitation.school or '',
            'major': invitation.major or '',
            
            # Anniversary specific
            'coupleNames': invitation.couple_names or '',
            'marriageYears': invitation.marriage_years or '',
            'husbandName': invitation.couple_names.split('&')[0].strip() if invitation.couple_names and '&' in invitation.couple_names else '',
            'wifeName': invitation.couple_names.split('&')[1].strip() if invitation.couple_names and '&' in invitation.couple_names else '',
            'husbandDescription': 'Loving Husband',
            'wifeDescription': 'Beloved Wife',
            'marriageYear': '1999',
            'firstMilestone': '2005',
            'secondMilestone': '2015',
            
            # Retirement specific
            'honoreeName': invitation.honoree_name or '',
            'position': invitation.position or '',
            'company': invitation.company or '',
            'startYear': invitation.start_year or '',
            
            # Contact info
            'hostName': invitation.host_name or '',
            'contactPhone': invitation.contact_phone or '',
            'contactEmail': invitation.contact_email or '',
            
            # Time and venue data (structured format)
            'timeData': {
                'muhurthamTime': invitation.muhurtham_time or '',
                'receptionTime': invitation.reception_time or '',
                'startTime': invitation.start_time or '',
                'dinnerTime': invitation.dinner_time or '',
                'partyTime': invitation.party_time or '',
                'anniversaryDinnerTime': invitation.anniversary_dinner_time or '',
                'babyshowerStartTime': invitation.babyshower_start_time or '',
                'babyshowerEndTime': invitation.babyshower_end_time or ''
            },
            'venueData': {
                'venue': invitation.venue_address or '',
                'address': invitation.venue_address or ''
            }
        }
        
        return render_template('invitation/view_final.html', invitation=invitation, event_data=event_data)

    @app.route('/edit-invitation/<int:invitation_id>', methods=['GET', 'POST'])
    def edit_invitation(invitation_id):
        if not is_authenticated():
            flash('Please login to continue', 'error')
            return redirect(url_for('auth'))
        
        invitation = Invitation.query.get_or_404(invitation_id)
        if invitation.user_id != session['user_id']:
            flash('Access denied', 'error')
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            try:
                # Update invitation data
                data = request.form
                
                # Update basic fields
                invitation.title = data.get('eventTitle', '')
                invitation.description = data.get('eventDescription', '')
                invitation.event_date = datetime.strptime(data.get('eventDate', ''), '%Y-%m-%d') if data.get('eventDate') else None
                
                # Update event-specific fields based on event type
                if invitation.event_type == 'wedding':
                    invitation.bride_name = data.get('brideName', '')
                    invitation.groom_name = data.get('groomName', '')
                    invitation.muhurtham_time = data.get('muhurthamTime', '')
                    invitation.reception_time = data.get('receptionTime', '')
                elif invitation.event_type == 'birthday':
                    invitation.birthday_person = data.get('birthdayPerson', '')
                    invitation.age = data.get('age', '')
                    invitation.start_time = data.get('startTime', '')
                    invitation.dinner_time = data.get('dinnerTime', '')
                elif invitation.event_type == 'babyshower':
                    invitation.mother_name = data.get('motherName', '')
                    invitation.father_name = data.get('fatherName', '')
                    invitation.start_time = data.get('babyshowerStartTime', '')
                    invitation.end_time = data.get('babyshowerEndTime', '')
                elif invitation.event_type == 'graduation':
                    invitation.graduate_name = data.get('graduateName', '')
                    invitation.degree = data.get('degree', '')
                    invitation.school = data.get('school', '')
                    invitation.major = data.get('major', '')
                elif invitation.event_type == 'anniversary':
                    invitation.couple_names = data.get('coupleNames', '')
                    invitation.marriage_years = data.get('marriageYears', '')
                    invitation.dinner_time = data.get('anniversaryDinnerTime', '')
                    invitation.party_time = data.get('partyTime', '')
                elif invitation.event_type == 'retirement':
                    invitation.honoree_name = data.get('honoreeName', '')
                    invitation.position = data.get('position', '')
                    invitation.company = data.get('company', '')
                    invitation.start_year = data.get('startYear', '')
                
                # Update contact information
                invitation.host_name = data.get('hostName', '')
                invitation.contact_phone = data.get('contactPhone', '')
                invitation.contact_email = data.get('contactEmail', '')
                invitation.venue_address = data.get('venueAddress', '')
                
                # Update style/religious preference
                invitation.event_style = data.get('eventStyle', '')
                
                invitation.updated_at = datetime.utcnow()
                db.session.commit()
                
                flash('Invitation updated successfully!', 'success')
                return redirect(url_for('view_invitation_manage', share_url=invitation.share_url))
                
            except Exception as e:
                app.logger.error(f"Error updating invitation: {str(e)}")
                db.session.rollback()
                flash('Error updating invitation. Please try again.', 'error')
        
        return render_template('invitation/edit.html', invitation=invitation)

    @app.route('/test-event-types')
    def test_event_types():
        try:
            event_types = EventType.query.all()
            return jsonify({
                'success': True,
                'count': len(event_types),
                'event_types': [{'id': et.id, 'name': et.name} for et in event_types]
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            })

# End of register_routes function
