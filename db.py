from perumal import app, db
with app.app_context():
    db.create_all()
    print("DB created")