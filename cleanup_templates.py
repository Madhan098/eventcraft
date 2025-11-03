#!/usr/bin/env python3
"""
Script to deactivate templates that don't have images in images/templatesimages/
"""

import os
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from app import app
from extensions import db
from models import Template

def cleanup_templates():
    """Deactivate templates without images in templatesimages folder"""
    with app.app_context():
        templates = Template.query.filter_by(is_active=True).all()
        deactivated = 0
        
        for template in templates:
            image_path = template.preview_image or ''
            
            # Only keep templates with images in images/templatesimages/
            if not image_path.startswith('/images/templatesimages/'):
                template.is_active = False
                deactivated += 1
                print(f"[DEACTIVATED] {template.name} ({template.event_type}) - No image in templatesimages/")
        
        db.session.commit()
        print(f"\n[COMPLETED]")
        print(f"   Deactivated: {deactivated} templates")
        
        # Show remaining active templates
        remaining = Template.query.filter_by(is_active=True).all()
        print(f"   Remaining active templates: {len(remaining)}")
        for t in remaining:
            print(f"     - {t.name} ({t.event_type})")

if __name__ == '__main__':
    cleanup_templates()

