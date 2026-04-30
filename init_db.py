from app import app, db, SystemSettingBool

with app.app_context():
    db.create_all()
    settings = [
        ('Registration','registration_enabled', True, True,True),
        ('Login','login_enabled', True, True,True),
        ('Hard Delete Tasks','perma_delete_task_enabled', False, False, True),
        ('Apple Calendar','apple_calendar', True, True, True),
        ('Start Date Injection','start_date_inject_default', True, True, True),
        ('User Settings','user_settings_access', True, True, False),
        ('API','api_enabled', True, True, False),
    ]
    
    # Iterate through settings data
    for label, key, value, expected_value, implemented in settings:
        
        # 1. Retrieve the actual object based on the label
        setting_to_delete = SystemSettingBool.query.filter_by(label=label).first()
        
        # 2. Check if the object exists (if setting_to_delete is not None)
        if setting_to_delete:
            
            # 3. Delete the found instance
            db.session.delete(setting_to_delete)
            
            # NOTE: If this is the last operation, commit the transaction
            # If this is part of a loop running many operations, you might commit outside the loop
            
    # 4. Commit all the changes made during the loop
    db.session.commit() 

    for label, key, value, expected_value, implemented in settings:
        if not SystemSettingBool.query.filter_by(label=label).first():
            db.session.add(SystemSettingBool(label=label,key=key, value=value, expected_value=expected_value, implemented=implemented))
    db.session.commit()
    print("Database initialized and default settings applied.")



