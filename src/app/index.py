import os

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from flask_bcrypt import Bcrypt
from google_recaptcha import ReCaptcha
import re
import random
import string
from flask_mail import Mail, Message
from sqlalchemy import create_engine, text
from datetime import date
from html import escape
import validators

from dotenv import load_dotenv

load_dotenv()

from flask import Flask

app = Flask(__name__)

alpha = False
beta = True

# Replace the following with your MySQL connection details

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER') or ''
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT') or 587
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME') or ''
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') or ''
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

recaptcha = ReCaptcha(
    app=app,
    site_key=os.getenv('RECAPTCHA_SITE_KEY') or '',
    site_secret=os.getenv('RECAPTCHA_SECRET_KEY') or '',
)

def generate_token():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))

username = os.getenv('DB_USERNAME') or 'root'
password = os.getenv('DB_PASSWORD') or ''
host = os.getenv('DB_HOST') or '127.0.0.1'
database = os.getenv('DB_NAME') or 'Postaverse'

# Creating the connection URL and engine
connection_url = f"mysql+mysqlconnector://{username}:{password}@{host}/{database}"
engine = create_engine(connection_url)

db = engine.connect()

def notifs():
    notifications1 = db.execute(text("SELECT * FROM Notifications WHERE user_id = :uid ORDER BY created_at DESC"), {'uid': session["user_id"]}).fetchall()
    return notifications1

def nCount():
    notifications2 = db.execute(text("SELECT COUNT(*) FROM Notifications WHERE user_id = :uid AND is_read = :i"), {'uid': session["user_id"], 'i': 0}).fetchone()
    return notifications2[0]


def sanitize(text):
    """Escape all HTML tags in the text, making it safe for rendering."""
    return escape(text)

def markup(text):
    # First, escape all HTML to prevent XSS
    text = sanitize(text)
    
    # Convert escaped **text** to <strong>text</strong>
    text = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)
    # Convert escaped *text* to <em>text</em>
    text = re.sub(r"\*(.*?)\*", r"<em>\1</em>", text)
    # Convert escaped ~text~ to <del>text</del>
    text = re.sub(r"~(.*?)~", r"<del>\1</del>", text)
    # Convert newlines to <br>, no need to escape since <br> is added by us and safe
    text = re.sub(r"\n", r"<br>", text)

    words = text.split()
    for i, word in enumerate(words):
        if validators.url(word):
            words[i] = f'<a href="{word}" target="_blank" class="see">{word}</a>'
    
    text = ' '.join(words)

    return text

@app.route("/ads.txt")
def adstxt():

    with open("ads.txt") as f:
        file_content = f.read()

    return file_content

@app.route("/", methods=["GET", "POST"])
def index():
    if session.get("name"):
        return redirect("/home")
    return render_template("index.html")

@app.route("/signup-page", methods=["GET", "POST"])
def signupPage():
    return render_template("signup.html")

@app.route("/login-page", methods=["GET", "POST"])
def loginPage():
    return render_template("login.html")

@app.route("/home", methods=["GET", "POST"])
def homeredirect():
    return redirect("/home/1")

@app.route("/home/<int:page>", methods=["GET", "POST"])
def home(page):
    per_page = 50
    offset = (page - 1) * per_page
    
    # Assuming db is your SQLAlchemy database instance
    posts = db.execute(text("SELECT Posts.*, Users.username, Users.display FROM Posts JOIN Users ON Posts.user_id = Users.user_id ORDER BY Posts.created_at DESC LIMIT :p OFFSET :o"), {'o': offset, 'p': per_page}).fetchall()

    processed_posts = []
    for post in posts:
        processed_content = markup(post.content)
        processed_post = post._asdict()
        processed_post['content'] = processed_content
        processed_posts.append(processed_post)
    
    nnCount = nCount()  # Your function to count notifications
    
    # Get the total number of posts to calculate total pages
    total_posts = db.execute(text("SELECT COUNT(*) FROM Posts")).scalar()
    total_pages = (total_posts + per_page - 1) // per_page
    
    return render_template("home.html", posts=processed_posts, notifcount=nnCount, total_pages=total_pages, current_page=page, per_page=per_page)

@app.route("/signup", methods=["POST"])
def signup():
    temp = 0
    if not recaptcha.verify() and not os.getenv('RECAPTCHA_SECRET_KEY'):
        error = "re-captcha failed."
        return render_template("signup.html", error=error)
        
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")
    dob = request.form.get("birth")
    u = username
    
    if not dob:
        error = "Date of Birth required."
        return render_template("signup.html", error=error)

    year, month, day = dob.split("-")

    # convert the strings to integers
    year = int(year)
    month = int(month)
    day = int(day)

    # create a date object from the user's input
    dobb = date(year, month, day)

    # get the current date
    today = date.today()

    # calculate the user's age in years
    age = today.year - dobb.year

    # adjust the age if the user's birthday has not passed yet
    if (today.month, today.day) < (dobb.month, dobb.day):
        age -= 1

    if not age >= 13:
        error = "Invalid Date of Birth."
        return render_template("signup.html", error=error)

    email_regex = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
    if not re.match(email_regex, email):
        error = "Invalid e-mail address."
        return render_template("signup.html", error=error)
    
    password_regex = r"(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}"
    if not re.match(password_regex, password):
        error = "Invalid password."
        return render_template("signup.html", error=error)

    if not username:
        error = "Username required."
        return render_template("signup.html", error=error)

    if db.execute(text("SELECT email FROM Users WHERE email = :email AND username = :username"), {'email': email, 'username': username}).fetchone():
        error = "e-mail already exists."
        return render_template("signup.html", error=error)
    if db.execute(text("SELECT username FROM Users WHERE username = :username"), {'username': username}).fetchone():
        while db.execute(text("SELECT username FROM Users WHERE username = :username"), {'username': u}).fetchone():
            i = 0
            u = username + str(i)
            i = i + 1


    u = u.replace(" ", "")
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    token = generate_token()
    
    while db.execute(text("SELECT token FROM Users WHERE token = :token"), {'token': token}).fetchone():
        token = generate_token()

    friendCode = generate_token()
    
    while db.execute(text("SELECT friend_code FROM Users WHERE friend_code = :token"), {'token': friendCode}).fetchone():
        friendCode = generate_token()

    db.execute(text("INSERT INTO Users (email, username, password_hash, token, dob, friend_code, timestamp) VALUES (:email, :username, :password_hash, :token, :dob, :friendcode, UTC_TIMESTAMP())"), {'email': email, 'friendcode': friendCode, 'username': u, 'password_hash': pw_hash, 'token': token, 'dob': dob})
    db.commit()
    if temp != 0:
        send_verification_email(email, token)
        return "Email Sent. Please open the link in the e-mail."
    return "Please send an email to `support@postaverse.net` with the email you signed up with to get verified. This is only temporary."

def send_verification_email(email, token):
    verification_link = "https://postaverse.net/verify/" + token
    msg = Message("Verify", 
                  body="Verify Your Email: " + verification_link,
                  sender="no-reply@postaverse.net",
                  recipients=[email])
    mail.send(msg)
    return ""

@app.route('/verify/<token>')
def verify(token):
    user = db.execute(text("SELECT * FROM Users WHERE token = :token"), {'token': token}).fetchone()
    if user:
        db.execute(text("UPDATE Users SET verified = 1 WHERE user_id = :user_id"), {'user_id': user.user_id})
        if alpha and not db.execute(text("SELECT * FROM Badges WHERE user_id = :uid"), {'uid': user.user_id}).fetchone():
            db.execute(text("INSERT INTO Badges (user_id, type) VALUES (:uid, :type)"), {'uid': user.user_id, 'type': "alpha-testing"})
        if beta and not db.execute(text("SELECT * FROM Badges WHERE user_id = :uid"), {'uid': user.user_id}).fetchone():
            db.execute(text("INSERT INTO Badges (user_id, type) VALUES (:uid, :type)"), {'uid': user.user_id, 'type': "beta-testing"})
        db.commit()

        session["user_id"] = user.user_id
        session["username"] = user.username

        return "Your email has been verified!"
    return "Invalid verification link"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    user = db.execute(text("SELECT * FROM Users WHERE username = :username"), {'username': username}).fetchone()
    admin = db.execute(text("SELECT username FROM Admins WHERE username = :u"), {'u': user.username}).fetchone()

    if user.verified != 1:
        error = "Email not verified."
        return render_template("login.html", error=error)
    # Check if username was found and password is correct
    if user and bcrypt.check_password_hash(user.password_hash, password):
        # User is authenticated, set up the session
        session["user_id"] = user.user_id
        session["name"] = user.username
        if admin:
            session["admin"] = admin.username
        else:
            session["admin"] = None
        return redirect("/home")
    else:
        # Username or password incorrect
        error = "Incorrect username or password."
        return render_template("login.html", error=error)

@app.route("/post-builder", methods=["POST", "GET"])
def postBuilder():
    if not session.get("name"):
        return redirect("/login-page")
    nnCount = nCount()
    return render_template("postbuilder.html", notifcount=nnCount)

@app.route("/post", methods=["POST"])
def post():
    name = request.form.get("name")
    content = request.form.get("post-content")
    user_id = session['user_id']
    user = db.execute(text("SELECT username FROM Users WHERE user_id = :fid"), {'fid': session["user_id"]}).fetchone()[0]
    followers = db.execute(text("SELECT * FROM Followers WHERE followed_id = :fid"), {'fid': session["user_id"]}).fetchall()

    if db.execute(text("SELECT * FROM Banned WHERE user_id = :uid"), {'uid': session["user_id"]}).fetchone():
        return "You are banned."
    
    db.execute(text("INSERT INTO Posts (user_id, content, created_at, name) VALUES (:id, :content, UTC_TIMESTAMP(), :name)"), {'id': user_id, 'content': content, 'name': name})

    post_id_result = db.execute(text("SELECT LAST_INSERT_ID()"))
    post_id = post_id_result.fetchone()[0]

    for follower in followers:
        follower_id = follower[0]  # Assuming this is the correct index for follower_id
        notification_message = f"User {user} made a new post"
        db.execute(text("INSERT INTO Notifications (user_id, message, created_at, post_id) VALUES (:user_id, :message, UTC_TIMESTAMP(), :pid)"), {'user_id': follower_id, 'message': notification_message, 'pid': post_id})

    db.commit()

    return redirect("/home")

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not session.get("name"):
        return "", 404

    name = session["admin"]
    admin = db.execute(text("SELECT * FROM Admins WHERE username = :username"), {'username': name}).fetchone()
    
    if admin:
        nnCount = nCount()
        return render_template("admin.html", name=name, admin=admin)
    return "", 404

@app.route("/delete-user-posts", methods=["GET", "POST"])
def deleteUserPosts():
    if db.execute(text("SELECT * FROM Admins WHERE username = :username"), {'username': session["name"]}).fetchone():
        username = request.form.get("username")
        user_result = db.execute(text("SELECT user_id FROM Users WHERE username = :username"), {'username': username}).fetchone()
        if user_result:
            user_id = user_result.user_id
            post_ids = db.execute(text("SELECT post_id FROM Posts WHERE user_id = :uid"), {'uid': user_id}).fetchall()
            for post in post_ids:
                db.execute(text("DELETE FROM Comments WHERE post_id = :pid"), {'pid': post.post_id})
                db.execute(text("DELETE FROM Likes WHERE post_id = :pid"), {'pid': post.post_id})
                db.execute(text("DELETE FROM Posts WHERE post_id = :pid"), {'pid': post.post_id})
                db.execute(text("DELETE FROM Notifications WHERE post_id = :pid"), {'pid': post.post_id})
            db.commit()
            return redirect("/admin")
        else:
            error = "User not found."
    else:
        return redirect("/home")

    name = session["name"]
    return render_template("admin.html", error=error, name=name)

@app.route("/profile/<int:user_id>", methods=["GET", "POST"])
def profile(user_id):
    # Fetch user information
    user_info = db.execute(text("SELECT * FROM Users WHERE user_id = :id"), {'id': user_id}).fetchone()
    id = db.execute(text("SELECT user_id FROM Users WHERE user_id = :id"), {'id': user_id}).fetchone()

    # If user does not exist, return a 404 error
    if not user_info:
        return "", 404
    
    uid = session["user_id"]

    if request.args.get("r") == "1" and request.args.get("p"):
        pid = request.args.get("p")
        db.execute(text("UPDATE Notifications SET is_read = 1 WHERE follow_id = :pid AND user_id = :uid"), {'pid': pid, 'uid': uid})
        db.commit()

    badges = db.execute(text("SELECT * FROM Badges WHERE user_id = :uid"), {'uid': id[0]}).fetchall()

    # Redirect to login page if not logged in
    if not session.get("user_id"):
        return redirect("/login-page")

    # Check if the logged-in user is following the profile owner
    following = db.execute(text("SELECT * FROM Followers WHERE follower_id = :follower_id AND followed_id = :followed_id"), {'follower_id': session.get("user_id"), 'followed_id': user_id}).fetchall()
    is_following = len(following) > 0

    # Get the count of followers for the user
    followers_count_query = db.execute(text("SELECT COUNT(*) as count FROM Followers WHERE followed_id = :followed_id"), {'followed_id': user_id}).fetchone()
    followers_count = followers_count_query.count

    # Fetch the latest 5 posts by the user
    posts = db.execute(text("SELECT * FROM Posts WHERE user_id = :id ORDER BY created_at DESC LIMIT 5"), {'id': user_id}).fetchall()

    processed_posts = []
    for post in posts:
        processed_content = markup(post.content)
        processed_post = post._asdict()
        processed_post['content'] = processed_content
        processed_posts.append(processed_post)

    # Render the profile page with the user info, posts, and follower details
    return render_template(
        "profile.html",
        user=user_info,
        profile_id=user_id,
        posts=processed_posts,
        is_following=is_following,
        followers_count=followers_count,
        badges=badges
    )

@app.route("/update-bio", methods=["POST"])
def updateBio():
    content = request.form.get("content")

    if db.execute(text("SELECT * FROM Banned WHERE user_id = :uid"), {'uid': session["user_id"]}).fetchone():
        return "You are banned."

    db.execute(text("UPDATE Users SET bio = :content WHERE username = :username"), {'content': content, 'username': session["name"]})
    db.commit()
    return redirect("/account")

@app.route("/logout", methods=["GET"])
def logout():
    session["name"] = None
    session["user_id"] = None
    if session["admin"] != None:
        session["admin"] = None

    return redirect("/login-page")

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/follow/<int:followed_id>', methods=['POST'])
def follow(followed_id):
    follower_id = session.get('user_id')
    if not follower_id:
        return redirect("/login-page")

    if follower_id == followed_id:
        return redirect(url_for('home'))

    if db.execute(text("SELECT * FROM Banned WHERE user_id = :uid"), {'uid': session["user_id"]}).fetchone():
        return "You are banned."

    db.execute(text("INSERT INTO Followers (follower_id, followed_id) VALUES (:follower_id, :followed_id)"), {'follower_id': follower_id, 'followed_id': followed_id})

    user = session["name"]

    notification_message = f"User {user} followed you"
    db.execute(text("INSERT INTO Notifications (user_id, message, created_at, follow_id) VALUES (:user_id, :message, UTC_TIMESTAMP(), :fid)"), {'user_id': followed_id, 'message': notification_message, 'fid': follower_id})

    db.commit()

    return redirect(url_for('profile', user_id=followed_id))

@app.route('/unfollow/<int:followed_id>', methods=['POST'])
def unfollow(followed_id):
    follower_id = session.get('user_id')
    if not follower_id:
        return redirect("/login-page")

    db.execute(text("DELETE FROM Followers WHERE follower_id = :follower_id AND followed_id = :followed_id"), {'follower_id': follower_id, 'followed_id': followed_id})
    db.commit()

    return redirect(url_for('profile', user_id=followed_id))

@app.route('/feed', methods=['GET', 'POST'])
def feeed():
    return redirect("/feed/1")

@app.route('/feed/<int:page>', methods=['GET', 'POST'])
def feed(page):
    
    temp = 0
    current_user_id = session.get('user_id')
    if not current_user_id:
        return redirect("/login-page")

    if temp == 1:
        return redirect("/home")
    nnCount = nCount()
    # Query to select posts that the current user follows
    followed_posts = db.execute(text("SELECT Posts.*, Users.username, Users.display FROM Posts JOIN Followers ON Posts.user_id = Followers.followed_id JOIN Users ON Posts.user_id = Users.user_id WHERE Followers.follower_id = :current_user_id ORDER BY Posts.created_at DESC"), {'current_user_id': session["user_id"]}).fetchall()

    # Query to select posts that the current user has liked
    liked_posts = db.execute(text("SELECT Posts.*, Users.username, Users.display FROM Posts JOIN Likes ON Posts.post_id = Likes.post_id JOIN Users ON Posts.user_id = Users.user_id WHERE Likes.user_id = :current_user_id ORDER BY Posts.created_at DESC"), {'current_user_id': session["user_id"]}).fetchall()

    your_posts = db.execute(text("SELECT Posts.*, Users.username, Users.display FROM Posts JOIN Users ON Posts.user_id = Users.user_id WHERE Users.user_id = :current_user_id ORDER BY Posts.created_at DESC"), {'current_user_id': session["user_id"]}).fetchall()

    # Combine the lists of posts, making sure to eliminate duplicates
    combined_posts = {post.post_id: post for post in followed_posts + liked_posts + your_posts}.values()

    # Sort the combined posts by creation time
    sorted_combined_posts = sorted(combined_posts, key=lambda post: post.created_at, reverse=True)

    per_page = 50
    offset = (page - 1) * per_page
    
    # Assuming db is your SQLAlchemy database instance
    posts = db.execute(text("SELECT Posts.*, Users.username, Users.display FROM Posts JOIN Users ON Posts.user_id = Users.user_id ORDER BY Posts.created_at DESC LIMIT :p OFFSET :o"), {'o': offset, 'p': per_page}).fetchall()
    
    nnCount = nCount()  # Your function to count notifications
    
    # Get the total number of posts to calculate total pages
    total_posts = db.execute(text("SELECT COUNT(*) FROM Posts")).scalar()
    total_pages = (total_posts + per_page - 1) // per_page

    processed_posts = []
    for post in sorted_combined_posts:
        processed_content = markup(post.content)
        processed_post = post._asdict()
        processed_post['content'] = processed_content
        processed_posts.append(processed_post)

    return render_template("feed.html", posts=processed_posts, notifcount=nnCount, total_pages=total_pages, current_page=page, per_page=per_page)


@app.route('/posts/<int:post_id>', methods=['GET'])
def viewPost(post_id):
    if not session.get("user_id"):
        return redirect("/login-page")
    nnCount = nCount()
    user_id = session["user_id"]

    if request.args.get("r") == "1" and request.args.get("r"):
        id = request.args.get("p")
        db.execute(text("UPDATE Notifications SET is_read = 1 WHERE post_id = :pid AND user_id = :uid"), {'pid': id, 'uid': user_id})
        db.commit()


    # Query to get the post details
    post = db.execute(text("SELECT Posts.*, Users.username, Users.display FROM Posts JOIN Users ON Posts.user_id = Users.user_id WHERE Posts.post_id = :post_id"), {'post_id': post_id}).fetchall()
    admin = db.execute(text("SELECT * FROM Admins WHERE username = :username"), {'username': session["name"]}).fetchone()
    # Check if the post exists
    if not post:
        return "Post not found", 404

    # Check if the post is liked by the current user
    liked_result = db.execute(text("SELECT 1 FROM Likes WHERE user_id = :uid AND post_id = :pid"), {'uid': user_id, 'pid': post_id}).fetchone()
    liked = 1 if liked_result else 0

    # Query to count the number of likes for the post
    likes_result = db.execute(text("SELECT COUNT(*) AS like_count FROM Likes WHERE post_id = :pid"), {'pid': post_id}).fetchone()
    likes = likes_result.like_count if likes_result else 0

    # Query to get the comments for the post
    comments = db.execute(text("SELECT Comments.*, Users.username, Users.display FROM Comments INNER JOIN Users ON Comments.user_id = Users.user_id WHERE post_id = :pid ORDER BY created_at DESC"), {'pid': post_id}).fetchall()

    processed_posts = []
    for post in post:
        processed_content = markup(post.content)
        processed_post = post._asdict()
        processed_post['content'] = processed_content
        processed_posts.append(processed_post)

    return render_template("post.html", comments=comments, post=processed_posts[0], liked=liked, likes=likes, admin=admin, notifcount=nnCount)

@app.route('/posts/<int:post_id>/comment', methods=['POST'])
def post_comment(post_id):
    if not session.get("user_id"):
        # Redirect the user to the login page if not logged in
        return redirect(url_for('login'))

    comment_content = request.form.get('comment_content')

    if db.execute(text("SELECT * FROM Banned WHERE user_id = :uid"), {'uid': session["user_id"]}).fetchone():
        return "You are banned."

    if not comment_content:
        flash('Comment cannot be empty!')
        return redirect(url_for('viewPost', post_id=post_id))

    db.execute(text("INSERT INTO Comments (post_id, user_id, content, created_at) VALUES (:pid, :uid, :content, UTC_TIMESTAMP())"), {'pid': post_id, 'uid': session['user_id'], 'content': comment_content})
    db.commit()

    return redirect(url_for('viewPost', post_id=post_id))

@app.route("/like/<int:post_id>", methods=["POST"])
def like_post(post_id):
    user_id = session["user_id"]
    # Check if the user has already liked the post
    likes_check = db.execute(text("SELECT * FROM Likes WHERE user_id = :uid AND post_id = :pid"), {'uid': user_id, 'pid': post_id}).fetchone()

    if db.execute(text("SELECT * FROM Banned WHERE user_id = :uid"), {'uid': session["user_id"]}).fetchone():
        return "You are banned."

    if not likes_check:
        # If not liked, insert like
        db.execute(text("INSERT INTO Likes (user_id, post_id) VALUES (:uid, :pid)"), {'uid': user_id, 'pid': post_id})
        liked = True
    else:
        # If already liked, remove like
        db.execute(text("DELETE FROM Likes WHERE user_id = :uid AND post_id = :pid"), {'uid': user_id, 'pid': post_id})
        liked = False
    db.commit()
    # Return a small script to update the parent page
    return '<script type="text/javascript">window.top.location.reload();</script>'

@app.route("/followers/<int:user_id>")
def followers(user_id):
    nnCount = nCount()
    # Query to get all follower_ids for the user_id
    followers_info = db.execute(text("SELECT follower_id FROM Followers WHERE followed_id = :uid"), {'uid': user_id}).fetchall()
    # Get details for each follower
    followers_details = [db.execute(text("SELECT * FROM Users WHERE user_id = :follower_id"), {'follower_id': f.follower_id}).fetchone() for f in followers_info]
    return render_template("followers.html", followers=followers_details, notifCount=nnCount)

@app.route("/add-admin", methods=["POST"])
def addAdmin():
    username = request.form.get("username")
    user = db.execute(text("SELECT * FROM Users WHERE username = :username"), {'username': username}).fetchone()

    db.execute(text("INSERT INTO Admins (username) VALUES (:username)"), {'username': username})
    db.execute(text("INSERT INTO Badges (user_id, type) VALUES (:uid, :type)"), {'uid': user.user_id, 'type': "admin"})
    db.commit()
    return redirect("/admin")

@app.route("/delete-post/<int:post_id>", methods=["GET"])
def deletePost(post_id):
    user_id = session.get("user_id")
    post = db.execute(text("SELECT user_id FROM Posts WHERE post_id = :pid"), {'pid': post_id}).fetchone()
    admin = db.execute(text("SELECT * FROM Admins WHERE username = :username"), {'username': session["name"]}).fetchone()

    if post and (post.user_id == user_id) or (admin):
        db.execute(text("DELETE FROM Likes WHERE post_id = :pid"), {'pid': post_id})
        db.execute(text("DELETE FROM Comments WHERE post_id = :pid"), {'pid': post_id})
        db.execute(text("DELETE FROM Posts WHERE post_id = :pid"), {'pid': post_id})
        db.execute(text("DELETE FROM Notifications WHERE post_id = :pid"), {'pid': post_id})
        db.commit()
        return redirect("/home")
    else:
        return "Error"


@app.route("/update-password", methods=["GET", "POST"])
def updatePassword():
    if request.method == "POST":
        # Assume user_id is obtained from the session after the user logs in
        user_id = session.get("user_id")

        # Check if the user is logged in
        if user_id is None:
            return "You must be logged in to change your password.", 403

        # Query database for user's current password hash
        user = db.execute(text("SELECT password_hash FROM Users WHERE user_id = :uid"), {'uid': user_id}).fetchone()
        if not user:
            return "User not found.", 404

        current_password_hash = user.password_hash

        # Get passwords from form input
        old_password = request.form.get("password")
        new_password = request.form.get("npassword")
        confirmation = request.form.get("n2password")

        # Verify old password
        if not bcrypt.check_password_hash(current_password_hash, old_password):
            return "Invalid password", 403

        # Check new password is provided and matches the confirmation
        if not new_password or new_password != confirmation:
            return "New password must be provided and both fields must match.", 400

        # Hash new password
        new_password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')

        # Update the password in the database
        db.execute(text("UPDATE Users SET password_hash = :ph WHERE user_id = :uid"), {'ph': new_password_hash, 'uid': user_id})
        db.commit()

        # Redirect to the admin page or confirmation page
        return redirect("/logout")

@app.route("/info", methods=["GET", "POST"])
def info():
    nnCount = nCount()
    return render_template("info.html", notifcount=nnCount)

@app.route("/account", methods=["GET", "POST"])
def account():
    error = ""
    nnCount = nCount()
    return render_template("account.html", notifcount=nnCount, error=error)

@app.route("/test", methods=["GET"])
def test():
    return render_template("db.html")

@app.route("/db", methods=["POST"])
def daba():
    user_id = session.get("user_id")
    dob = request.form.get("birth")
    db.execute(text("UPDATE Users SET dob = :dob WHERE user_id = :uid"), {'dob': dob, 'uid': user_id})
    db.commit()
    return redirect("/home")

@app.route("/db-f", methods=["POST"])
def dabaf():
    friendCode = generate_token()
        
    while db.execute(text("SELECT friend_code FROM Users WHERE friend_code = :token"), {'token': friendCode}).fetchone():
        friendCode = generate_token()

    user_id = session.get("user_id")
    db.execute(text("UPDATE Users SET friend_code = :fc WHERE user_id = :uid"), {'fc': friendCode, 'uid': user_id})
    db.commit()
    return redirect("/home")

@app.route("/report-admin", methods=["POST"])
def adminReport():
    pid = request.form.get("pid")

    db.execute(text("INSERT INTO Reports (post_id, reporter_id) VALUES (:pid, :uid)"), {'pid': pid, 'uid': session["user_id"]})
    db.commit()
    return "reported"

@app.route("/badges", methods=["POST", "GET"])
def badgePage():
    nnCount = nCount()
    alpha = db.execute(text("SELECT COUNT(*) FROM Badges WHERE type = :type"), {'type': 'alpha-testing'}).fetchone()
    beta = db.execute(text("SELECT COUNT(*) FROM Badges WHERE type = :type"), {'type': 'beta-testing'}).fetchone()
    admin = db.execute(text("SELECT COUNT(*) FROM Badges WHERE type = :type"), {'type': 'admin'}).fetchone()
    imposter = db.execute(text("SELECT COUNT(*) FROM Badges WHERE type = :type"), {'type': 'imposter'}).fetchone()

    return render_template("badges.html", alpha=alpha[0], beta=beta[0], admin=admin[0], imposter=imposter[0], notifcount=nnCount)

@app.route("/notifications", methods=["GET", "POST"])
def notif():
    n = notifs()
    return render_template("notifications.html", notifs=n)

@app.route("/betaaa")
def betaaa():
    y = 0
    if y == 0:
        post_ids = db.execute(text("SELECT post_id FROM Posts")).fetchall()
        for post in post_ids:
            db.execute(text("DELETE FROM Comments WHERE post_id = :pid"), {'pid': post.post_id})
            db.execute(text("DELETE FROM Likes WHERE post_id = :pid"), {'pid': post.post_id})
            db.execute(text("DELETE FROM Posts WHERE post_id = :pid"), {'pid': post.post_id})
            db.execute(text("DELETE FROM Notifications WHERE post_id = :pid"), {'pid': post.post_id})
        db.commit()
        

    return redirect("/home")

@app.route("/display-name-change", methods=["POST"])
def dNC():
    display = request.form.get("display")
    
    db.execute(text("UPDATE Users SET display = :d WHERE user_id = :uid"), {'d': display, 'uid': session["user_id"]})
    db.commit()

    return redirect("/account")

@app.route("/get-user", methods=["POST"])
def get_user():
    username = request.form.get('username')  # Get the username from request arguments
    if not username:
        return jsonify({'error': 'Username parameter is missing'}), 400
    
    u = username
    i = -1
    
    

    # Check if the username exists and find a unique variant
    while db.execute(text("SELECT username FROM Users WHERE username = :username"), {'username': u}).fetchone():
        i += 1
        u = username + str(i)

    u = u.replace(" ", "")

    return jsonify({'username': u})
