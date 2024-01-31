import csv
import datetime
import pytz
import requests
import subprocess
import urllib
import uuid

from flask import redirect, render_template, session
from functools import wraps
import http.client, urllib.parse


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Prepare API request
    symbol = symbol.upper()
    end = datetime.datetime.now(pytz.timezone("US/Eastern"))
    start = end - datetime.timedelta(days=7)

    # Yahoo Finance API
    url = (
        f"https://query1.finance.yahoo.com/v7/finance/download/{urllib.parse.quote_plus(symbol)}"
        f"?period1={int(start.timestamp())}"
        f"&period2={int(end.timestamp())}"
        f"&interval=1d&events=history&includeAdjustedClose=true"
    )

    # Query API
    try:
        response = requests.get(url, cookies={"session": str(uuid.uuid4())}, headers={"User-Agent": "python-requests", "Accept": "*/*"})
        response.raise_for_status()

        # CSV header: Date,Open,High,Low,Close,Adj Close,Volume
        quotes = list(csv.DictReader(response.content.decode("utf-8").splitlines()))
        quotes.reverse()
        price = round(float(quotes[0]["Adj Close"]), 2)
        return {
            "name": symbol,
            "price": price,
            "symbol": symbol
        }
    except (requests.RequestException, ValueError, KeyError, IndexError):
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"

def time():
    """Get current time one day ago."""
    current_time = datetime.datetime.now(pytz.timezone("US/Eastern"))
    one_day_ago = current_time - datetime.timedelta(days=1)
    formatted_time = one_day_ago.strftime("%Y-%m-%dT%H:%M")
    return formatted_time

def news(symbols: list, filter: bool, industry, published_after=time()): #Not enough time to implement this function
    """Look up news for country and sector."""
    # Prepare API request
    industry = industry.lower()
    symbols = ','.join([s.upper().replace(' ', '') for s in symbols])
    filter = str(filter).lower()

    API_TOKEN = "yrPDwJxKwD0wPma7nXyzBjCxqRXM39LBFv78qvRl" #for testing purposes only

    conn = http.client.HTTPSConnection('api.marketaux.com')

    params = urllib.parse.urlencode({
        'api_token': API_TOKEN,
        'symbols': symbols,
        'limit': 10,
        'filter_entities': filter,
        'industry': industry,
        })

    conn.request('GET', '/v1/news/all?{}'.format(params))

    res = conn.getresponse()
    data = res.read()

    print(data.decode('utf-8'))




