"""
finance.py

Inleiding dataverwerking en webtechnieken - Final Project

This program is a web application that allows users to manage portfolios of stocks.
The application lets users "buy" and "sell" stocks by querying Yahoo for stocks' prices.

Personal touch: added a delete account function, a deposit function, a withdraw function,
a change password function and a change username function.

Sander Murray - 14861291
"""

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

def check_shares_input(raw) -> int:
    if raw.isnumeric():
        return int(raw)
    else:
        return 0 #to trip the check

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.context_processor
def header():
    if 'user_id' in session:
        user_info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if user_info:
            username = user_info[0]["username"]
            cash = user_info[0]["cash"]
            return dict(user=username, cash=cash)
    return {}


@app.route("/") #TODO ADD COMMENTS
@login_required
def index():
    """Show portfolio of stocks"""
    if 'user_id' in session:
        user_id = session["user_id"]
        portfolio = db.execute("SELECT symbol, name, SUM(shares), price FROM trades WHERE user_id = :user_id GROUP BY symbol HAVING SUM(shares) > 0 ORDER BY price DESC",
                                user_id=user_id)
        user_info = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        cash = user_info[0]['cash']
        current_total = cash
        for stock in portfolio:
            stock_current = lookup(stock["symbol"])
            stock["current_price"] = stock_current["price"]
            stock["total_price"] = stock_current["price"] * stock["SUM(shares)"]
            profitability = round(((stock_current["price"] / stock["price"]) * 100) - 100, 2)
            stock["profitability"] = f"+{profitability}" if profitability > 0 else str(profitability)
            current_total += stock["total_price"]
        return render_template("index.html", portfolio=portfolio, user_cash=cash, current_total=current_total)
    else:
        return apology("Something went wrong", 500)


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

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
                db.execute("INSERT INTO trades (user_id, symbol, name, shares, price) VALUES (:user_id, :symbol, :name, :shares, :price)",
                            user_id=user_id,
                            symbol=f'{symbol}',
                            name=f'{symbol}', #until solution found
                            shares=f'{shares}',
                            price=price_share)

                db.execute("UPDATE users SET cash = :cash WHERE id == :id", cash=balance_new, id=f'{user_id}')
                flash(f"Successfully bought {shares} share's of {symbol}!")
                return render_template("buy.html")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_transactions = db.execute("SELECT user_id, symbol, shares, price, time FROM trades WHERE user_id = ? ORDER BY time", session["user_id"])

    return render_template("history.html", user_transactions=user_transactions)


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
    user_id = session["user_id"]
    if request.method == "POST":
        #setting local veriables
        symbol = request.form.get("symbol").upper()
        shares_raw = request.form.get("shares")
        stock = lookup(symbol)
        shares = check_shares_input(shares_raw) #check if fail

        if stock is None or shares < 1:
            return apology("Invalid input, try again.")
        
        rows = db.execute("SELECT symbol, name, shares, price FROM trades WHERE user_id == :user_id AND symbol = :symbol",
                            user_id=user_id,
                            symbol=symbol)
        
        current_shares = 0
        for row in rows:
            current_shares += int(row["shares"])
        
        if current_shares < shares:
            return apology("Not enough shares")
        
        db.execute("UPDATE users SET cash = cash + :value WHERE id = :id",
                    value=stock["price"] * shares,
                    id=user_id)
        
        db.execute("INSERT INTO trades (user_id, symbol, name, shares, price) VALUES (:user_id, :symbol, :name, :shares, :price)",
                            user_id=user_id,
                            symbol=f'{symbol}',
                            name=f'{symbol}', #until solution found
                            shares=f'{shares * (-1)}',
                            price=stock["price"])
        
        flash("Success! Yippie!")
        return render_template("sell.html")
    else:
        rows = db.execute("SELECT symbol FROM trades WHERE user_id = :user_id",
                            user_id=user_id)
        return render_template("sell.html", symbols=[row["symbol"] for row in rows])
    
@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    user_id = session["user_id"]
    if request.method == "POST":
        db.execute("DELETE FROM trades WHERE user_id == :user_id",
            user_id=user_id)
        db.execute("DELETE FROM users WHERE id == :id",
                    id=user_id)
        session.clear()
        return redirect("/")
    else:
        return render_template("delete.html")
    
@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    user_id = session["user_id"]
    deposit = request.form.get("deposit")
    if deposit.isnumeric():
        deposit = int(deposit)
    else:
        return apology("NaN")
    db.execute("UPDATE users SET cash = cash + :deposit WHERE id == :id",
                deposit=deposit,
                id=user_id)
    flash(f"Successfully deposited {usd(deposit)}!")
    return redirect("/")

@app.route("/withdraw", methods=["POST"])
@login_required
def withdraw():
    user_id = session["user_id"]
    withdraw = request.form.get("withdraw")
    if withdraw.isnumeric():
        withdraw = int(withdraw)
    else:
        return apology("NaN")
    balance = db.execute("SELECT cash FROM users WHERE id == ?", user_id)[0]['cash']
    if balance < withdraw:
        return apology("Insufficient funds")
    else:
        db.execute("UPDATE users SET cash = cash - :withdraw WHERE id == :id",
                    withdraw=withdraw,
                    id=user_id)
        flash("Success! See you in Monaco!")
        return redirect("/")

@app.route("/change_pass", methods=["POST"])
@login_required
def change_pass():
    user_id = session["user_id"]
    password = request.form.get("new_password")

    if not password:
        return apology("Enter a password")

    password_hash = generate_password_hash(password)
    current_hash = db.execute("SELECT hash FROM users WHERE id == :id",
                                id=user_id)[0]["hash"]
    if check_password_hash(current_hash, password):
        return apology("New password cannot be the same as the old one")
    else:
        db.execute("UPDATE users SET hash = :password WHERE id == :id",
                    password=password_hash,
                    id=user_id)
        flash("Success! Password changed!")
        return redirect("/")
    
@app.route("/change_user", methods=["POST"])
@login_required
def change_user():
    user_id = session["user_id"]
    username = request.form.get("new_username").lower()

    if not username:
        return apology("Enter a username")

    if db.execute("SELECT username FROM users WHERE username == ?", username):
        return apology("username already in use, try another.")
    else:
        db.execute("UPDATE users SET username = :username WHERE id == :id",
                    username=username,
                    id=user_id)
        flash("Success! Username changed!")
        return redirect("/")