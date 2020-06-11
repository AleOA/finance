import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("postgres://drgkcitoocnpxg:06898384bd96f2b9842ba1d68b5451fd8fb16927fd85fcbdb02aa46a2f6c8b50@ec2-34-232-147-86.compute-1.amazonaws.com:5432/d85u8pt04kcm94")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    users = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])
    stocks = db.execute("SELECT shares, stock as stock_symbol FROM bought WHERE username = :username", username= username[0]["username"])
    q_dict = {}

    for stock in stocks:
        q_dict[stock["stock_symbol"]] = lookup(stock["stock_symbol"])

    available_cash = users[0]["cash"]

    stocks_total_value = 0

    for stock in stocks:
        stocks_total_value += q_dict[stock["stock_symbol"]]["price"] * stock["shares"]

    total_cash = available_cash + stocks_total_value

    return render_template("index.html", q_dict=q_dict, stocks=stocks, total_cash=total_cash, available_cash=available_cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    else:
        if len(request.form.get("symbol")) < 1 or lookup(request.form.get("symbol")) == None:
            return apology("STOCK symbol is not valid.", 403)

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("shares must be a positive integer", 403)

        if shares <= 0:
            return apology("You need to buy at least 1 Share.", 403)

        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        get_username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])

        username = get_username[0]["username"]

        stock_info = lookup(request.form.get("symbol"))
        available_cash = rows[0]["cash"]
        price_per_share = stock_info["price"]

        stock_to_buy = request.form.get("symbol").upper()

        shares = request.form.get("shares")

        total_price = int(shares) * float(price_per_share)

        if total_price > available_cash:
            return apology("You do not have enough funds to complete the transaction", 403)

        db.execute("UPDATE users SET cash = cash - :price WHERE id = :user_id", price=total_price, user_id=session["user_id"])

        list_current_stocks = []

        current_stocks_symbols = db.execute("SELECT stock FROM bought WHERE username=:username", username=username)

        for i in range(0, len(current_stocks_symbols)):
            list_current_stocks.append(current_stocks_symbols[i]["stock"])


        if stock_to_buy in list_current_stocks:
            stock_shares_dict = db.execute("SELECT shares FROM bought WHERE stock = :symbol AND username=:username", username=username, symbol=stock_info["symbol"])
            new_stock_shares = stock_shares_dict[0]["shares"] + int(shares)
            db.execute("UPDATE bought SET shares = :new_stock_shares WHERE stock = :stock_to_buy AND username=:username", new_stock_shares=new_stock_shares, stock_to_buy=stock_to_buy, username=username)
        else:
            db.execute("INSERT INTO bought (username, shares, stock) VALUES(:username, :shares, :stock)",
                   username=username, shares=shares, stock=stock_info["symbol"])

        now = datetime.now()
        date = now.strftime("%d/%m/%Y %H:%M:%S")

        db.execute("INSERT INTO history (username, shares, stock, price, date) VALUES(:username, :shares, :stock, :price, :date)", username=username, shares=shares, stock=stock_info["symbol"], price=str(stock_info["price"]), date=date)

        return redirect("/")



@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    get_username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])

    username = get_username[0]["username"]

    history_data = db.execute("SELECT username, shares, stock, price, date FROM history WHERE username=:username", username=username)

    return render_template("history.html", history_data=history_data)




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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    if request.method == "GET":
        return render_template("quote.html")

    else:
        stock_info = lookup(request.form.get("symbol"))

        if stock_info == None:
            return apology("This stock does not exist", 403)

        return render_template("quoted.html", stock_info=stock_info)



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if not request.form.get("username") or len(rows) == 1:
            return apology("You can not leave this empty or username is already in use", 403)
        else:
            correct_username = request.form.get("username")

        if request.form.get("password") != request.form.get("confirmation") or len(request.form.get("password")) == 0:
            return apology("Passwords does not match or are empty", 403)
        else:
            correct_password = request.form.get("password")
            hashed_password = generate_password_hash(correct_password)

        new_user = db.execute("INSERT INTO users (username, hash) VALUES(:correct_username, :hashed_password)", correct_username=correct_username, hashed_password=hashed_password)

        session["user_id"] = new_user

        return redirect("/")

    if request.method == "GET":
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "GET":
        get_username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])

        username = get_username[0]["username"]

        stocks = db.execute(
            "SELECT stock, shares FROM bought WHERE username = :username", username=username)
        return render_template("sell.html", stocks=stocks)
    else:

        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("shares must be a positive integer", 403)

        if shares <= 0:
            return apology("You need to sell at least 1 Share.", 403)

        get_username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])

        username = get_username[0]["username"]

        stock_info = lookup(request.form.get("symbol"))
        price_per_share = stock_info["price"]

        stock_to_sell = request.form.get("symbol").upper()

        shares_to_sell = int(request.form.get("shares"))

        total_price = shares_to_sell * float(price_per_share)


        current_shares_dict = db.execute("SELECT shares FROM bought WHERE stock=:stock_to_sell AND username=:username", stock_to_sell=stock_to_sell, username=username)
        current_shares = current_shares_dict[0]["shares"]

        if shares_to_sell > current_shares:
            return apology("You can not sell more shares than you currently have", 403)
        if shares_to_sell == current_shares:
            db.execute("DELETE FROM bought WHERE username=:username AND stock=:stock_to_sell", username=username, stock_to_sell=stock_to_sell)
        if shares_to_sell < current_shares:
            db.execute("UPDATE bought SET shares = shares - :shares_to_sell WHERE username=:username AND stock=:stock_to_sell", shares_to_sell=shares_to_sell, username=username, stock_to_sell=stock_to_sell)

        now = datetime.now()
        date = now.strftime("%d/%m/%Y %H:%M:%S")

        db.execute("INSERT INTO history (username, shares, stock, price, date) VALUES(:username, :shares, :stock, :price, :date)", username=username, shares="-" + str(shares), stock=stock_info["symbol"], price=str(stock_info["price"]), date=date)
        db.execute("UPDATE users SET cash = cash + :total_price WHERE id = :user_id", total_price=total_price, user_id=session["user_id"])

        return redirect("/")

@app.route("/addcash", methods=["GET", "POST"])
@login_required
def addcash():
    if request.method == "GET":
        return render_template("addcash.html")
    else:
        get_username = db.execute("SELECT username FROM users WHERE id = :user_id", user_id=session["user_id"])

        username = get_username[0]["username"]

        value_selected = int(request.form.get("cash"))

        db.execute("UPDATE users SET cash = cash + :value_selected WHERE username=:username", value_selected=value_selected, username=username)

        now = datetime.now()
        date = now.strftime("%d/%m/%Y %H:%M:%S")

        db.execute("INSERT INTO history (username, shares, stock, price, date) VALUES(:username, :shares, :stock, :price, :date)", username=username, shares="None", stock="CASH", price=str(value_selected), date=date)

        return redirect("/")






def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
