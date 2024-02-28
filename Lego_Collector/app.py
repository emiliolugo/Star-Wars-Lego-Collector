import os
from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import custom_error, login_required, lookup
# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL('sqlite:///star_wars_lego.db')

#Global all_sets variable
all_sets = db.execute(
        "SELECT * FROM sets"
    )
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    #Generate greeting for user
    users = db.execute("SELECT username FROM users WHERE id = ?", session["user_id"])
    user = users[0]["username"]

    #Make dropdown list of all sets
    sets = db.execute("SELECT * FROM sets")

    #remember how many sets the user owns
    owned_sets = db.execute(
            "SELECT COUNT(set_num) AS count FROM user_items WHERE user_id = ?" , session["user_id"]
            )
    owned = owned_sets[0]["count"]
    if not owned_sets:
        owned = 0
    owned_sets = db.execute(
            '''SELECT * FROM sets, user_items WHERE sets.set_num = user_items.set_num
            AND user_items.user_id = ?''' , session["user_id"]
            )
    # find oldest and newest set they own
    old_set = db.execute(
        '''SELECT * FROM sets, user_items 
            WHERE sets.set_num = user_items.set_num
            AND user_id = ?
            ORDER BY sets.year'''
            , session["user_id"]
        )
    new_set = db.execute(
        '''SELECT * FROM sets, user_items 
            WHERE sets.set_num = user_items.set_num
            AND user_id = ?
            ORDER BY sets.year DESC'''
            , session["user_id"]
        )
    set_dates = None

    if old_set and new_set:
        set_dates = [old_set[0], new_set[0]]

    return render_template('index.html', 
    user = user, sets = sets, owned = owned, set_dates = set_dates,
    owned_sets = owned_sets)


    

    
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return custom_error("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return custom_error(403,"must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return custom_error("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        
        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html", )

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
   
@app.route("/register", methods = ["GET","POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            bad_user = True
            return render_template("register.html", bad_user = bad_user)

        # Ensure password was submitted
        # TODO make sure passwords have 8 character restriction
        elif not request.form.get("password"):
            bad_pass = True
            return render_template("register.html", bad_pass = bad_pass)
        #Ensure password is confirmed
        elif not (request.form.get("password") == request.form.get("conf")):
            bad_conf = True
            return render_template("register.html", bad_conf = bad_conf)
        # Check if username is available
        user_list = []
        usernames = db.execute("SELECT username FROM users")
        username = request.form.get("username")
        for row in usernames:
            user_list.append(row['username'])
        if username in user_list:
            return render_template("register.html", bad_user = bad_user)

        # Create username and hash for password
        db.execute(
            "INSERT INTO users(username, hash) VALUES(?,?)", username,
            generate_password_hash(request.form.get("password"))
            )
        #redirect them to the home page
        #TODO auto login
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")
    
@app.route("/set/<set_num>", methods=["GET", "POST"])
def set(set_num):
    if request.method == "POST":
        # Check if user added to user_items
        owned_value = request.form.get("owned")
        if owned_value == "1":
            # Check if user already owns
            owned_sets = db.execute(
                "SELECT set_num FROM user_items WHERE user_id = ? AND set_num = ?",
                session["user_id"],
                set_num,
            )
            if not owned_sets:
                db.execute(
                    "INSERT INTO user_items(user_id, set_num) VALUES (?, ?)",
                    session["user_id"],
                    set_num,
                )
        else:
            db.execute(
                "DELETE FROM user_items WHERE user_id = ? AND set_num = ?",
                session["user_id"],
                set_num,
            )
        return redirect("/")

    else:
        #Get set info if redirected to page
        set_info = db.execute("SELECT * FROM sets WHERE set_num = ?", set_num)
        #Check if individual has owned the set
        owned_sets = db.execute(
            '''SELECT * FROM user_items WHERE user_items.set_num = ?
            AND user_items.user_id = ?''', set_num , session["user_id"]
            )
        if owned_sets:
            owned = True
        else:
            owned = False
        return render_template("set.html", set_info = set_info, owned = owned, all_sets = all_sets)

@app.route("/wishlist", methods=["GET", "POST"])
def wishlist():
    wished_sets = None
    if request.method == "POST":
        if request.form.get("lego_set"):
            set_num = request.form.get("lego_set")
            # Check if set is already in wishlist
            wished_sets = db.execute(
                "SELECT set_num FROM wishlist WHERE user_id = ? AND set_num = ?",
                session["user_id"], set_num
            )
            if not wished_sets:
                db.execute(
                    '''INSERT INTO wishlist(user_id, set_num)
                    VALUES (?, ?)''',
                    session["user_id"], set_num
                )
                

    # Fetch wished sets
    wished_sets = db.execute(
        '''SELECT * FROM sets, wishlist 
           WHERE wishlist.user_id = ? AND sets.set_num = wishlist.set_num''',
        session["user_id"],
    )

    return render_template("wishlist.html", wished_sets=wished_sets, all_sets = all_sets)

@app.route("/sets")
def sets():
    return render_template("sets.html", all_sets = all_sets)
        
@app.route("/")
def layout():
    sets = db.execute("SELECT name FROM sets")
    return layout("layout.html", all_sets = all_sets)