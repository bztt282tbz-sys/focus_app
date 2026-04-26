from app import app, db, SystemSetting

with app.app_context():
    db.create_all()
    
    # Initialize default settings if they don't exist
    settings = [
        ('registration_enabled', True),
        ('login_enabled', True)
    ]
    
    for key, value in settings:
        if not SystemSetting.query.filter_by(key=key).first():
            db.session.add(SystemSetting(key=key, value=value))
    
    db.session.commit()
    print("Database initialized and default settings applied.")