import os
import requests

from flask import redirect, render_template, request, session
from functools import wraps
from haversine import haversine, Unit

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def distance(location_a, location_b):
    if location_a[0] == None or location_a[1] == None or location_b[0] == None or location_b[1] == None:
        return None
    dis = haversine(location_a, location_b, unit=Unit.MILES)
    return "{:.2f}".format(dis)