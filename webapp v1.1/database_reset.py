# Code to reset the banking.db database clean
from app import db,app

# THIS CODE IS MEANT TO BE RUN BY THE DEVELOPER ONLY
# IT WILL RESET THE DATABASE TO A CLEAN STATE
# DO NOT RUN THIS CODE IF YOU ARE NOT THE DEVELOPER

app.app_context().push()
db.drop_all()
db.create_all()
db.session.commit()

print("Database has been cleared and reset successfully!")