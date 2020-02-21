#*******************************Imports*************************
import os
from flask import Flask, render_template, request, url_for, session, redirect, send_from_directory
import random
from FlaskLoginSystem import LoginManager
from sqlalchemy import create_engine
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import smtplib

#***************************Flask Initialization******************
app = Flask(__name__)
app.config["SECRET_KEY"] = b'\x05\xdb\x03\xbc\xbfW\x8a\x04\xf6\xd4\x85\xdd\x80\x8d@\x9b\n\xe6\x83\xdd$\xeb\xdad'

img_upload_folder = os.path.join(app.root_path, "static\\res")

#***********************Global Variables******************
login_manager = LoginManager("sqlite:///Users.db", "UserCredentials", ["Id", "Username", "Password", "Email", "EmailVerified", "PasswordChangeRequested"], 0, [3], [2, 3], [2])
allowed_file_extensions = ["jpg", "png"]

#*************************Routing**********************
@app.route("/", methods=["GET", "POST"])
def login() :
    """The login page"""
    
    if(login_manager.get_current_user() == None) :
        if(request.method == "GET") :
            return render_template("login.html")
        else :
            user_data = {'Email' : request.form["email"], 'Password' : request.form["pss"]}

            if(login_manager.log_user(user_data) == 0) :
                session.permanent = False
                return redirect(f"{url_for('current_user')}")
    else :
        return redirect(f"{url_for('current_user')}")


@app.route("/signup", methods=["GET", "POST"])
def sign_up() :
    """The sign up page"""

    if(login_manager.get_current_user() == None) :
        if(request.method == "POST") :
            global registered_users
            
            user_data = {"Id" : login_manager.number_of_registered_users(), "Username" : request.form["usrnm"], "Password" : request.form["psswrd"], "Email" : request.form["email"], "EmailVerified" : 0, "PasswordChangeRequested": 0}

            if(login_manager.register_user(user_data) == -1) :
                return "<h1> Email already registered </h1>"
            else :
                session.permanent = False
                send_verification_email(user_data["Email"], user_data["Id"])
                return redirect(f"{url_for('get_user_details')}")
        else :
            return render_template("sign_up.html")
    else :
        return redirect(f"{url_for('current_user')}")

@app.route("/user_details", methods=["GET", "POST"])
def get_user_details() :

    if(request.method == "GET") :
        if(login_manager.get_current_user() == None) :
            return redirect(f"{url_for('login')}")
        else :
            return render_template("user_details.html")
    else :
        db_conn = create_engine("sqlite:///Users.db", echo=True).connect()

        #Getting the uploaded file
        uploaded = request.files['img']
        #Checking if the file extension is allowed
        if(not filename_is_allowed(uploaded.filename)) :
            return "<h1> Invalid File </h1>"

        #Converting the file name to a secure form
        secured_filename = secure_filename(uploaded.filename)
        #Saving the uploaded file
        uploaded.save(os.path.join(img_upload_folder, secured_filename))

        cmd = f"""INSERT INTO UserInfo(Id, FirstName, LastName, Birthdate, UserId, ImgPath) VALUES ('{get_table_size("UserInfo")}',
        '{request.form['frstnm']}', '{request.form['lstnm']}', '{request.form['brthd']}', '{login_manager.get_current_user()}', 
        '{secured_filename}' )"""

        db_conn.execute(cmd)
        db_conn.close()

        return redirect(f"{url_for('current_user')}")

@app.route("/user/pic")
def show_user_pic() :

    if(login_manager.get_current_user() != None) :
        
        db_conn = create_engine("sqlite:///Users.db", echo=True).connect()

        cmd = f"SELECT * FROM UserInfo WHERE UserId = {login_manager.get_current_user()}"
        user_profile = list(db_conn.execute(cmd))[0]

        db_conn.close()

        return send_from_directory(img_upload_folder, user_profile[-1])

    else :
        return redirect(f"{url_for('login')}")


@app.route("/logout")
def logout() :

    login_manager.log_user_out()

    return redirect(f"{url_for('login')}")

@app.route("/user", methods=["GET","POST"])
def current_user() :
    
    if(login_manager.get_current_user() != None) :
        if(request.method == "GET") :
            db_conn = create_engine("sqlite:///Users.db", echo=True).connect()

            cmd = f"SELECT * FROM UserInfo WHERE UserId = {login_manager.get_current_user()}"

            user_info = list(db_conn.execute(cmd))
            print(len(user_info))

            db_conn.close()

            return render_template("current_user.html", first_name=user_info[0][1], last_name=user_info[0][2], birthdate=user_info[0][3], path=f"../static/res/{user_info[0][5]}")      
        else :
            login_manager.log_user_out()
            return redirect(f"{url_for('login')}")
    else :
        return redirect(f"{url_for('login')}")

@app.route("/forgot_password/email", methods=["GET", "POST"])
def forgot_password_email() :

    if(request.method == "POST") :
        email = request.form['email']

        user = login_manager.get_user_by_credentials({"Email" : email})
        if(user != None) :
            send_password_change_link(email, user[0][0])
            return "<h1> An email was sent to your registered email address with the link to change the password </h1>"
    else :
        return render_template("change_password_email.html")

@app.route("/verify/<user_id>")
def verify_user_email(user_id) :

    if(login_manager.update_user_credentials(user_id, {"EmailVerified": 1}) == 0) :
        return "<h1> Your email has been verified </h1>"

@app.route("/change_password/<user_id>", methods=["GET", "POST"])
def change_password(user_id) :

    if(request.method == "GET") :
        return render_template("change_password.html")
    else :
        
        if(login_manager.get_user_by_primary_key(user_id)[5] == 1) :
            login_manager.update_user_credentials(user_id, {"Password" : request.form['newpss'], "PasswordChangeRequested" : 0})
            return redirect(f"{url_for('login')}")
        else :
            return "<h1> No password change requested </h1>"

@app.route("/delete_user")
def delete_user() :

    if(login_manager.get_current_user() != None) :
        if(login_manager.delete_user(login_manager.get_current_user()) == 0) :
            return "<h1> User deleted </h1>"
    else :
        return redirect(f"{url_for('login')}")



def filename_is_allowed(filename) :

    file_extension = filename.rsplit('.')[-1]

    if(not file_extension in allowed_file_extensions) :
        return False

    return True

def get_table_size(table) :

    db_conn = create_engine("sqlite:///Users.db").connect()

    cmd = f"SELECT COUNT(Id) FROM {table}"
    res = db_conn.execute(cmd).first().values()[0]

    db_conn.close()

    return res

def send_verification_email(email_addr, user) :

    sender_addr = os.environ.get("DEV_EMAIL_ADDR")
    sender_pss = os.environ.get("DEV_EMAIL_PSS")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp :
        smtp.login(sender_addr, sender_pss)

        email_msg = f"""Subject: Email Verification Link\n\nClick on this link to complete email verification link:\n
        http://localhost:5000/verify/{user}"""

        smtp.sendmail(sender_addr, email_addr, email_msg)

        print(f"Verification email sent to {email_addr}")

def send_password_change_link(email_addr, user) :

    sender_addr = os.environ.get("DEV_EMAIL_ADDR")
    sender_pss = os.environ.get("DEV_EMAIL_PSS")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp :
        smtp.login(sender_addr, sender_pss)

        email_msg = f"""Subject: Password Change Link\n\nClick on this link to change the password:\n
        http://localhost:5000/change_password/{user}"""

        smtp.sendmail(sender_addr, email_addr, email_msg)

        login_manager.update_user_credentials(user, {"PasswordChangeRequested" : 1})


#************************Script Commands******************
if(__name__ == "__main__") :
    app.run()
