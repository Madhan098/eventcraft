import os
import logging
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from extensions import db
import json

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get("SESSION_SECRET", "eventcraft-secret-key-2024")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure session
from datetime import timedelta
app.permanent_session_lifetime = timedelta(days=7)  # Sessions last 7 days

# Configure the database
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    # Default to SQLite for development
    db_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'database'))
    os.makedirs(db_dir, exist_ok=True)
    db_file = os.path.join(db_dir, 'eventcraft.db')
    database_url = f'sqlite:///{db_file}'

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.abspath(os.path.join(os.path.dirname(__file__), 'uploads'))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB max file size

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize the app with the extension
db.init_app(app)

# Add custom Jinja2 filters
@app.template_filter('fromjson')
def fromjson_filter(value):
    if value:
        return json.loads(value)
    return {}

@app.template_filter('from_json')
def from_json_filter(value):
    if value:
        return json.loads(value)
    return {}

# Add custom Jinja2 functions
@app.template_global('template_exists')
def template_exists(template_path):
    """Check if a template exists"""
    try:
        app.jinja_env.get_template(template_path)
        return True
    except:
        return False

# Add context processor to make session available in templates
@app.context_processor
def inject_session():
    from flask import session
    return dict(session=session)

# Add CORS headers
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Add a simple test route


# Import models first
try:
    import models  # noqa: F401
    print("✅ Models imported successfully")
except Exception as e:
    print(f"❌ Error importing models: {e}")
    import traceback
    traceback.print_exc()

# Initialize database and sample data
with app.app_context():
    try:
        db.create_all()
        print("✅ Database tables created successfully")

        # Initialize sample data if tables are empty
        from models import init_sample_data
        if not models.EventType.query.first():
            init_sample_data()
            print("✅ Sample data initialized successfully")
            
    except Exception as e:
        print(f"❌ Error during database initialization: {e}")
        import traceback
        traceback.print_exc()

# Import and register routes AFTER app context is set up
try:
    print("🔄 Attempting to import routes...")
    from routes import register_routes
    print("✅ Routes module imported successfully")
    
    print("🔄 Attempting to register routes...")
    register_routes(app)
    print("✅ Routes registered successfully")
    
except Exception as e:
    print(f"❌ Error during route registration: {e}")
    import traceback
    traceback.print_exc()
    
    # Fallback: Add basic routes manually
    print("🔄 Adding fallback routes...")
    try:
        from flask import render_template
        
        @app.route('/')
        def index():
            return render_template('index.html')
        
        @app.route('/auth')
        def auth():
            return render_template('auth/login.html')
        

        
        print("✅ Fallback routes added successfully")
        
    except Exception as fallback_error:
        print(f"❌ Error adding fallback routes: {fallback_error}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)