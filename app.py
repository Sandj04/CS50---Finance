import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


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
    """Show portfolio of stocks"""
    user_info = db.execute("SELECT * FROM users WHERE id == ? LIMIT 1", session["user_id"]) #limit 1?
    username = user_info[0]['username']
    cash = user_info[0]['cash']
    rows = db.execute("SELECT * FROM portfolio WHERE user_id == ?", session["user_id"])
    total = cash
    for row in rows:
        total += row['price_total']
        row['price_share'] = usd(row['price_share'])
        row['price_total'] = usd(row['price_total'])
    return render_template("index.html", user=f'{username}', rows=rows, cash=f'{usd(cash)}', total=f'{usd(total)}')


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get('symbol')
        shares_raw = request.form.get('shares')
        if shares_raw.isnumeric():
            shares = int(shares_raw)
        else:
            return apology("Shares NaN")

        output_lookup = lookup(symbol)
        if not output_lookup or shares < 1:
            return apology("Enter valid input")
        else:
            user_id = session["user_id"]
            price_share = output_lookup['price']
            price_total = price_share * shares
            balance = db.execute("SELECT cash FROM users WHERE id == ?", user_id)[0]['cash']
            balance_new = balance - price_total

            if balance_new < 0:
                return apology("Insufficient funds")
            else:
                db.execute("INSERT INTO portfolio (user_id, symbol, shares, price_share, price_total) VALUES (:user_id, :symbol, :shares, :price_share, :price_total)",
                            user_id=user_id,
                            symbol=f'{symbol}',
                            shares=f'{shares}',
                            price_share=price_share,
                            price_total=price_total)
                db.execute("UPDATE users SET cash = :cash WHERE id == :id", cash=balance_new, id=f'{user_id}')
                flash("Submitted your child\'s college fund")
                return render_template("buy.html")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get('symbol')
        output_lookup = lookup(symbol)

        if output_lookup:
            name = output_lookup['name']
            price = usd(output_lookup['price'])
            flash('Form submitted successfully!')
            return render_template('quoted.html', name=name, symbol=symbol, price=price)
        else:
            return apology('Enter a valid symbol', 404)
    else:
        return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    if request.method == "POST":
        #sets payload enitities to local variables
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        #checks if pass and user are provided
        if not username:
            return apology("must provide username", 403)
        elif not password:
            return apology("must provide password", 403)
        
        #checks if username taken
        if db.execute("SELECT username FROM users WHERE username == ?", username):
            return apology("username already in use, try another.")
        
        #checks if passwords match, then stores in database after hashing
        if password != confirmation:
            return apology("passwords do not match", 403)
        else:
            password_hash = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
                        username=f'{username}',
                        password=f'{password_hash}')
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")
