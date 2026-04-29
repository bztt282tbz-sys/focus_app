from app import app, db, SystemSettingBool

with app.app_context():
    db.create_all()
    settings = [
        ('Registration','registration_enabled', True, True,True),
        ('Login','login_enabled', True, True,True),
        ('Hard Delete Tasks','perma_delete_task_enabled', False, False, True),
        ('Apple Calendar','apple_calendar', True, True, True),
        ('Start Date Injection','start_date_inject_default', True, True, True),
        ('API','api_enabled', True, True, False),
    ]
    for label, key, value, expected_value, implemented in settings:
        if not SystemSettingBool.query.filter_by(label=label).first():
            db.session.add(SystemSettingBool(label=label,key=key, value=value, expected_value=expected_value, implemented=implemented))
    db.session.commit()
    print("Database initialized and default settings applied.")



