#!/usr/bin/env python3
"""
Script to sync template images from images/templatesimages folder to database
Run this script to add/update templates based on images in the folder
"""

import os
import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from app import app
from extensions import db
from models import Template, EventType

def sync_templates_from_folder():
    """Sync templates from images/templatesimages folder"""
    templates_folder = Path('images/templatesimages')
    
    if not templates_folder.exists():
        print(f"Folder {templates_folder} does not exist!")
        return
    
    template_images = list(templates_folder.glob('*.png')) + list(templates_folder.glob('*.jpg')) + list(templates_folder.glob('*.jpeg'))
    
    print(f"Found {len(template_images)} template images")
    
    with app.app_context():
        # Create event types if they don't exist
        wedding_type = EventType.query.filter_by(name='wedding').first()
        if not wedding_type:
            wedding_type = EventType(
                name='wedding',
                display_name='Wedding',
                description='Celebrate the union of two hearts',
                icon='fas fa-heart',
                color='#e91e63',
                sort_order=1,
                is_active=True
            )
            db.session.add(wedding_type)
            db.session.commit()
        
        imported_count = 0
        updated_count = 0
        
        for img_path in template_images:
            # Extract template name from filename
            filename = img_path.stem  # Get name without extension
            filename_lower = filename.lower()
            
            # Determine event type from filename
            # Check for specific patterns first (e.g., "wedding anniversary" should be anniversary)
            event_type = 'birthday'  # Default
            if 'anniversary' in filename_lower:
                event_type = 'anniversary'
            elif 'wedding' in filename_lower:
                event_type = 'wedding'
            elif 'birthday' in filename_lower:
                event_type = 'birthday'
            elif 'babyshower' in filename_lower or 'baby' in filename_lower:
                event_type = 'babyshower'
            elif 'graduation' in filename_lower or 'grduation' in filename_lower:
                event_type = 'graduation'
            elif 'retirement' in filename_lower:
                event_type = 'retirement'
            
            # Generate template name from filename
            template_name = filename
            
            # Clean up the name - remove common suffixes
            template_name = template_name.replace(' Mobile Video', '').replace(' Mobile', '').strip()
            template_name = template_name.replace('_', ' ').replace('-', ' ')
            
            # Capitalize properly
            words = template_name.split()
            template_name = ' '.join(word.capitalize() for word in words)
            
            # Handle specific patterns
            if 'cream and pink wedding anniversary' in filename_lower:
                template_name = 'Cream and Pink Wedding Anniversary'
            elif 'ballonbirthday' in filename_lower or 'ballon birthday' in filename_lower:
                template_name = 'Balloon Birthday'
            elif 'birthdayblackgold' in filename_lower or 'birthday black gold' in filename_lower:
                template_name = 'Black Gold Birthday'
            elif 'birthdaycolourful' in filename_lower or 'birthday colourful' in filename_lower:
                template_name = 'Colorful Birthday'
            elif 'cream and pink floral wedding' in filename_lower:
                template_name = 'Cream and Pink Floral Wedding'
            elif 'pastel romantic wedding' in filename_lower:
                template_name = 'Pastel Romantic Wedding'
            elif filename_lower == 'wedding':
                template_name = 'Elegant Wedding'
            
            if not template_name:
                template_name = filename.replace('_', ' ').title()
            
            # Image path relative to images folder
            image_path = f'/images/templatesimages/{img_path.name}'
            
            # Check if template exists (by name and event type to avoid duplicates)
            existing_template = Template.query.filter_by(name=template_name, event_type=event_type).first()
            
            if existing_template:
                # Update existing template
                existing_template.preview_image = image_path
                existing_template.is_active = True
                updated_count += 1
                print(f"[UPDATED] {template_name} ({event_type})")
            else:
                # Create new template
                new_template = Template(
                    name=template_name,
                    description=f'Elegant {template_name} invitation template',
                    event_type=event_type,
                    religious_type='general',
                    style='modern',
                    color_scheme='A07878',
                    preview_image=image_path,
                    is_active=True
                )
                db.session.add(new_template)
                imported_count += 1
                print(f"[IMPORTED] {template_name} ({event_type})")
        
        db.session.commit()
        print(f"\n[COMPLETED]")
        print(f"   Imported: {imported_count} new templates")
        print(f"   Updated: {updated_count} existing templates")
        print(f"   Total: {imported_count + updated_count} templates processed")

if __name__ == '__main__':
    sync_templates_from_folder()

