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


@app.route("/") #TODO ADD COMMENTS
@login_required
def index():
    """Show portfolio of stocks"""
    user_info = db.execute("SELECT * FROM users WHERE id == ?", session["user_id"])
    username = user_info[0]['username']
    cash = user_info[0]['cash']
    rows = db.execute("SELECT * FROM portfolio WHERE user_id == ?", session["user_id"])
    total = cash
    for row in rows:
        stock = lookup(row['symbol']) #VERY SLOW LOADING, MAYBE LOADING SCREEN
        current_price = stock['price']
        row['price_share'] = usd(current_price)
        row['price_total'] = usd(current_price * row['shares'])
        total += current_price * row['shares']
    return render_template("index.html", user=username, rows=rows, cash=usd(cash), total=usd(total))


@app.route("/buy", methods=["GET", "POST"]) #TODO ADD COMMENTS, FIX MULTIPLE OF SAME STOCK IF SOLD TO 0
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get('symbol').upper()
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
                check = db.execute("SELECT symbol, shares FROM portfolio WHERE user_id == ? AND symbol == ?", user_id, symbol)
                if len(check) > 0:
                    db.execute("UPDATE portfolio SET shares = shares + :value WHERE user_id == :user_id AND symbol == :symbol",
                            user_id=user_id,
                            value=shares,
                            symbol=f'{symbol}')
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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username").lower())

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
        symbol = request.form.get('symbol').upper()
        output_lookup = lookup(symbol)

        if output_lookup:
            name = output_lookup['name']
            price = usd(output_lookup['price'])
            flash('Form submitted successfully!')
            return render_template('quoted.html', name=name, symbol=symbol, price=price)
        else:
            return apology('Enter a valid symbol', 400)
    else:
        return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()

    if request.method == "POST":
        #sets payload enitities to local variables
        username = request.form.get("username").lower()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        #checks if pass and user are provided
        if not username:
            return apology("must provide username", 400)
        elif not password:
            return apology("must provide password", 400)
        
        #checks if username taken
        if db.execute("SELECT username FROM users WHERE username == ?", username):
            return apology("username already in use, try another.")
        
        #checks if passwords match, then stores in database after hashing
        if password != confirmation:
            return apology("passwords do not match", 400)
        else:
            password_hash = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
                        username=f'{username}',
                        password=f'{password_hash}')
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"]) #TODO ADD COMMENTS, FIX STOCK NUMBER SET AT 0 IN INDEX
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol").upper()
        shares_raw = request.form.get("shares")
        stock = lookup(symbol)
        if shares_raw.isnumeric():
            shares = int(shares_raw)
        else:
            return apology("Shares NaN")

        if stock is None or shares < 1:
            return apology("Invalid input")

        rows = db.execute("SELECT shares FROM portfolio WHERE user_id = :user_id AND symbol = :symbol",
                            user_id=session["user_id"],
                            symbol=symbol)

        if len(rows) != 1 or rows[0]["shares"] < shares:
            return apology("Not enough shares")

        db.execute("UPDATE users SET cash = cash + :value WHERE id = :id",
                    value=stock['price'] * shares,
                    id=session["user_id"])

        remaining_shares = rows[0]["shares"] - shares
        if remaining_shares == 0:
            db.execute("DELETE FROM portfolio WHERE user_id = :user_id AND symbol = :symbol",
                        user_id=session["user_id"],
                        symbol=symbol)
        else:
            db.execute("UPDATE portfolio SET shares = :shares WHERE user_id = :user_id AND symbol = :symbol",
                        shares=remaining_shares,
                        user_id=session["user_id"],
                        symbol=symbol)

        flash("Successfully sold, yippie")
        return render_template("sell.html")
    else:
        rows = db.execute("SELECT symbol FROM portfolio WHERE user_id = :user_id",
                            user_id=session["user_id"])
        return render_template("sell.html", symbols=[row["symbol"] for row in rows])
