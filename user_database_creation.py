#*******************************Imports*************************
from sqlalchemy import create_engine

#*******************************Sript Commands*************************
engine = create_engine("sqlite:///Users.db", echo=True)

"""cmd = CREATE TABLE UserInfo(
        Id INT NOT NULL PRIMARY KEY,
        FirstName TEXT NOT NULL,
        LastName TEXT NOT NULL,
        Birthdate TEXT NOT NULL,
        UserId INT references UserCredentials(Id))"""

#cmd = "ALTER TABLE UserInfo ADD ImgPath TEXT"

#cmd = "ALTER TABLE UserCredentials ADD EmailVerified INT"

cmd = "ALTER TABLE UserCredentials ADD PasswordChangeRequested INT"


conn = engine.connect()
res = conn.execute(cmd)