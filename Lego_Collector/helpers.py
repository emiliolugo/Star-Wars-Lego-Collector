import csv
import datetime
import urllib
import uuid
import requests

from cs50 import SQL
from flask import redirect, render_template, session,abort
from functools import wraps

#Rebrickable API Ket
API_KEY = '53f76a37206e84278ef4641f96d6b8e5'

# Base URL for Rebrickable API
BASE_URL = 'https://rebrickable.com/api/v3'

# Connect SQL database
db = SQL('sqlite:///star_wars_lego.db')

headers = {
    'Authorization': f'key {API_KEY}'
}
# Make a GET request to the API
def lookup(set_id):
    url = f'{BASE_URL}/sets/{set_id}/'
    response = requests.get(url, headers=headers)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the JSON response
        data = response.json()
        # Example: Print the name of the set
        print('Set Name:', data['name'])
    else:
        print('Failed to retrieve data:', response.status_code)


#create error
def custom_error(message, status_code = 400):
    abort(status_code, message)

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

#Store data in sql table
def get_sets_in_theme(theme_id):
    url = f'https://rebrickable.com/api/v3/lego/sets/?theme_id={theme_id}'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f'Failed to retrieve data: {response.status_code}')
        return None
    
ids = [18,158,209]
for id in ids:
    sets_data = get_sets_in_theme(id)
    if sets_data is not None and 'results' in sets_data:
        for set_data in sets_data['results']:
            #Check if set is in the database
            existing_set = db.execute(
                "SELECT set_num FROM sets WHERE set_num = ?", (set_data["set_num"],)
            )
            if existing_set:
                db.execute(
                    '''UPDATE sets
                    SET set_num = ?, name = ?, year = ?, num_parts = ?, image = ?
                    WHERE set_num = ?''',
                    set_data["set_num"], set_data["name"], set_data["year"], set_data["num_parts"], set_data["set_img_url"]
                    , set_data["set_num"]
                )
            else:    
                db.execute(
                    "INSERT INTO sets (set_num, name, year, num_parts, image) VALUES (?, ?, ?, ?, ?)",
                    set_data["set_num"], set_data["name"], set_data["year"], set_data["num_parts"], set_data["set_img_url"]
                )
