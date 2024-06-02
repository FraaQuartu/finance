from flask import Flask, flash, url_for, redirect, render_template, request, session, get_flashed_messages
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from typing import List
from sqlalchemy import text, Column, Table, ForeignKey, Integer, DateTime, Float
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd
app.secret_key = "xwkmfelhrsf3429342$%/$%&"

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///finance.db"
app.secret_key = "wdkfqldk"
Session(app)


class Base(DeclarativeBase):
    pass

db = SQLAlchemy(app, model_class=Base)


class User(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str]
    hash: Mapped[str]
    cash: Mapped[float] = mapped_column(default=10000.00)

class UserStock(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    stock_symbol: Mapped[str]
    timestamp: Mapped[datetime] = mapped_column(default=lambda x: datetime.now())
    shares: Mapped[int]
    price_per_share: Mapped[float]
    total_price: Mapped[float]


with app.app_context():
    db.create_all()

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
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol")
        symbol_dict = lookup(symbol)
        if symbol_dict is None:
            return apology("Symbol does not exists")

        shares = int(request.form.get("shares"))
        if shares <= 0:
            return apology("Shares must be a positive integer")

        symbol = symbol_dict["symbol"]
        price = symbol_dict["price"]
        
        user_id = session["user_id"]
        user = User.query.filter_by(id=user_id).first()
        cash = user.cash
        total_price = price*shares
        if cash < shares * price:
            return apology("You cannot afford it")

        # Insert
        user_stock = UserStock(user_id=user_id, stock_symbol=symbol, shares=shares, price_per_share=price, total_price=total_price)
        db.session.add(user_stock)

        user.cash = cash - total_price
        db.session.commit()
        return redirect("/")

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

        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()

        # Ensure username exists and password is correct
        if user is None or not check_password_hash(
            user.hash, password
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = user.id

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
        symbol = request.form.get("symbol")
        symbol_dict = lookup(symbol)
        if symbol_dict is None:
            return apology("Invalid symbol")

        value = symbol_dict["price"]
        symbol = symbol_dict["symbol"]
        return render_template("quoted.html", symbol=symbol, value=value)
    
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)
        
        username = request.form.get("username")
        user = User.query.filter_by(username=username).first()

        if user is not None:
            return apology("Username already exists")
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Insert into database
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        if password != confirm_password:
            return apology("Passwords do not match")
        
        hash = generate_password_hash(password)
        user = User(username=username, hash=hash)
        db.session.add(user)
        db.session.commit()

        session["user_id"] = user.id
        flash("User successfully registered!")
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")
