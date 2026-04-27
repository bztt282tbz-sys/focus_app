from app import app, db, SystemSettingBool

with app.app_context():
    db.create_all()
    settings = [
        ('Registration','registration_enabled', True, True),
        ('Login','login_enabled', True, True),
        ('API','api_enabled', False, True)
    ]
    for label, key, value, expected_value in settings:
        if not SystemSettingBool.query.filter_by(label=label).first():
            db.session.add(SystemSettingBool(label=label,key=key, value=value,expected_value=expected_value))
    db.session.commit()
    print("Database initialized and default settings applied.")

