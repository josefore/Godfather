import os
import requests

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, distance

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Expires'] = 0
    response.headers['Pragma'] = 'no-cache'
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config['SESSION_FILE_DIR'] = mkdtemp()
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL('sqlite:///godfather.db')

if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route('/')
def index():
    if 'user_id' in session.keys():
        return redirect('/home')

    # Start page which introduces the basic concepts of the site
    return render_template('index.html')


@app.route('/home')
@login_required
def home():
    user_id = session['user_id']
    loc_off = 1
    location = db.execute('SELECT latitude, longitude FROM users WHERE id = ?;', user_id)

    if location[0]['latitude'] == None or location[0]['longitude'] == None:
        loc_off = 0

    session['tokens'] = db.execute('SELECT tokens FROM users WHERE id = ?;', user_id)[0]['tokens']
    requests = db.execute('SELECT COUNT(request_id) FROM requests WHERE user_id = ?;', user_id)[0]['COUNT(request_id)']
    replies = db.execute('SELECT COUNT(reply_id) FROM replies WHERE user_id = ?;', user_id)[0]['COUNT(reply_id)']

    # Check for notifications i.e. payments received
    pays = db.execute('SELECT reply_id, seen, sender_id, amount FROM transactions WHERE receiver_id = ?;', user_id)

    return render_template('home.html', tokens=session['tokens'], requests=requests, replies=replies, loc=loc_off, pays=pays)


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'GET':
        return render_template('signin.html')

    else:
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        newsletter = ''

        if username == None or email == None or password == None or password_confirm == None:
            return render_template('error.html', errno=400, error='must fill in all fields', redir='/signin')

        pwHash = generate_password_hash(password)
        usernames = db.execute('SELECT username, email FROM users;')
        users = []
        for e in usernames:
            users.append((e['username'], e['email']))
        # Check username and email don't exist
        if users != []:
            for f in users:
                if f[0] == username:
                    return render_template('error.html', errno=400, error='user already exists', redir='/signin')
                if f[1] == email:
                    return render_template('error.html', errno=400, error='email already registered, go back to recover your password', redir='/recover')

        # Check for terms and conditions agreement
        if not request.form.get('terms-conf'):
            return render_template('error.html', errno=400, error='must agree with terms and conditions if you want enter our comunity', redir='/signin')

        #Check for newsletter
        if not request.form.get('news-lett'):
            newsletter = 'TRUE'
        else:
            newsletter = 'FALSE'

        # Check if confirm password is correct
        if check_password_hash(pwHash, password_confirm):
            db.execute('INSERT INTO users (username, hash, email, nletter) VALUES (?, ?, ?, ?);', username, pwHash, email, newsletter)
            return redirect('/login')

        return render_template('error.html', errno=400, error='password confirmation does not match', redir='/signin')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == 'POST':
        # Ensure username was submitted
        if not request.form.get('username'):
            return render_template('error.html', errno=403, error='must provide username', redir='/login')

        # Ensure password was submitted
        elif not request.form.get('password'):
            return render_template('error.html', errno=403, error='must provide password', redir='/login')

        # Query database for username
        rows = db.execute('SELECT * FROM users WHERE username = ? OR email = ?;', request.form.get('username'), request.form.get('email'))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]['hash'], request.form.get('password')):
            return render_template('error.html', errno=403, error='invalid username', redir='/login')

        # Remember which user has logged in
        session['user_id'] = rows[0]['id']
        session['tokens'] = rows[0]['tokens']

        # Redirect user to home page
        return redirect('/')

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template('login.html')


@app.route('/logout')
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect('/')


@app.route('/location', methods=['GET', 'POST'])
@login_required
def locate():
    api_key = os.environ.get('API_KEY')
    if request.method == 'POST':
        URL = 'https://geocode.search.hereapi.com/v1/geocode'
        location = request.form.get('location')
        PARAMS = {'apikey':api_key,'q':location}

        # sending get request and saving the response as response object
        r = requests.get(url = URL, params = PARAMS)
        data = r.json()

        latitude = data['items'][0]['position']['lat']
        longitude = data['items'][0]['position']['lng']

        return render_template('map.html', apikey=api_key, latitude=latitude, longitude=longitude)

    else:
        coordinates = db.execute('SELECT latitude, longitude FROM users WHERE id = ?;', session['user_id'])
        if coordinates[0]['latitude'] == None or coordinates[0]['longitude'] == None:
            return render_template('location.html', apikey=api_key, latitude=40.58939, longitude=(-73.66608))

        latitude = coordinates[0]['latitude']
        longitude = coordinates[0]['longitude']
        return render_template('location.html', apikey=api_key, latitude=latitude, longitude=longitude)


@app.route('/location_confirm', methods=['POST'])
@login_required
def confirm_location():
    lat = request.form.get('latitude')
    lng = request.form.get('longitude')
    db.execute('UPDATE users SET latitude = ?, longitude = ? WHERE id = ?', lat, lng, session['user_id'])
    return render_template('loconf_success.html')


@app.route('/request', methods=['GET', 'POST'])
@login_required
def request_help():
    if request.method == 'GET':
        return render_template('request.html')
    else:
        if not (request.form.get('title') and request.form.get('description') and request.form.get('day') and request.form.get('month') and request.form.get('year') and request.form.get('category') and request.form.get('difficulty') and request.form.get('completion') and request.form.get('offer')) or not request.form.get('offer').isnumeric():
            return render_template('error.html', errno=501, error='must fill in all the request fields', redir='/request')

        # Check if request does not exist already
        user = session['user_id']
        title = request.form.get('title')
        check = db.execute('SELECT COUNT(request_id) FROM requests WHERE user_id = ? AND title = ?;', user, title)[0]['COUNT(request_id)']
        if check != 0:
            return render_template('error.html', errno=400, error='request already exist, delete previous request to continue', redir='/myrequests')

        # Format date in deadline
        day = ''
        if len(request.form.get('day')) == 1:
            day = '0' + request.form.get('day')
        else:
            day = request.form.get('day')
        deadline = request.form.get('year') + '-' + request.form.get('month') + '-' + day + ' 00:00:00'

        # Check if user can afford it
        tok = db.execute('SELECT tokens FROM users WHERE id = ?;', user)[0]['tokens']
        if int(request.form.get('offer')) > tok:
            return render_template('error.html', errno=400, error='not enough tokens', redir='/request')

        db.execute('INSERT INTO requests (user_id, difficulty, time_elapse, deadline, offer, description, category, title) VALUES (?, ?, ?, ?, ?, ?, ?, ?);', user, request.form.get('difficulty'), request.form.get('completion'), deadline, request.form.get('offer'), request.form.get('description'), request.form.get('category'), title)

        session['last_request'] = db.execute('SELECT request_id FROM requests WHERE user_id = ? AND title = ?;', user, title)[0]['request_id']

        loc = db.execute('SELECT latitude, longitude FROM users WHERE id = ?;', user)
        lat = loc[0]['latitude']
        lng = loc[0]['longitude']

        if not request.form.get('location-change'):
            if lat == None or lng == None:
                return render_template('error.html', errno=404, error='you have not set a personal location, go back to set one', redir='/loc_change')

            db.execute('UPDATE requests SET lat = ?, lng = ? WHERE request_id = ?;', lat, lng, session['last_request'])

        elif request.form.get('location-change') == '1':
            return redirect('/loc_change')

        return redirect('/myrequests')


# This function handles both methods GET and POST because if the location displayed in mapchange.html is unaccurate, it still can access the id of the request we are changing location of and try as many times as we need, which is stored in the global variable session['last_request']
@app.route('/loc_change', methods=['POST', 'GET'])
@login_required
def loc_change():
    api_key = os.environ.get('API_KEY')
    if request.method == 'POST':
        URL = 'https://geocode.search.hereapi.com/v1/geocode'
        if not requet.form.get('location'):
            return render_template('error.html', errno=400, error='you have not selected any location', redir='/loc_change')
        location = request.form.get('location')
        PARAMS = {'apikey':api_key,'q':location}

        # sending get request and saving the response as response object
        r = requests.get(url = URL, params = PARAMS)
        data = r.json()

        latitude = data['items'][0]['position']['lat']
        longitude = data['items'][0]['position']['lng']

        return render_template('mapchange.html', apikey=api_key, latitude=latitude, longitude=longitude)

    else:
        coordinates = db.execute('SELECT latitude, longitude FROM users WHERE id = ?;', session['user_id'])
        if coordinates[0]['latitude'] == None or coordinates[0]['longitude'] == None:
            return render_template('locchange.html', apikey=api_key, latitude=40.58939, longitude=(-73.66608))

        latitude = coordinates[0]['latitude']
        longitude = coordinates[0]['longitude']
        return render_template('locchange.html', apikey=api_key, latitude=latitude, longitude=longitude)


@app.route('/map_confirm', methods=['POST'])
@login_required
def conf_task_loc():
    lat = request.form.get('latitude')
    lng = request.form.get('longitude')

    db.execute('UPDATE requests SET lat = ?, lng = ? WHERE request_id = ?', lat, lng, session['last_request'])

    return redirect('/myrequests')


@app.route('/myrequests', methods=['GET', 'POST'])
@login_required
def my_requests():
    if request.method == 'POST':
        req = int(request.form.get('reqst'))
        data = db.execute('SELECT title, description, offer, category, req_date, time_elapse, deadline, difficulty, FROM requests WHERE request_id = ?;', req)
        rep = db.execute('SELECT COUNT(reply_id) FROM  replies WHERE request_id = ? AND NOT status = "rejected";', req)[0]['COUNT(reply_id)']
        dt = data[0]
        return render_template('singlereq.html', data=dt, req=req, replies=rep)
    else:
        overall = db.execute('SELECT title, description, offer, req_date, request_id FROM requests WHERE user_id = ? AND status = FALSE;', session['user_id'])

        # Count replies for each request
        data = []
        for row in overall:
            row['reps'] = db.execute('SELECT COUNT(reply_id) FROM replies WHERE request_id = ? AND NOT status = "rejected";', row['request_id'])[0]['COUNT(reply_id)']
            data.append(row)

        return render_template('myrequests.html', requests=data)


@app.route('/del_req', methods=['POST'])
@login_required
def del_req():
    req = request.form.get('req')
    db.execute('DELETE FROM requests WHERE request_id = ?;', req)
    return redirect("/myrequests")


@app.route('/replies', methods=['POST'])
@login_required
def replies():
    req = request.form.get('req')
    rep = db.execute('SELECT replies.reply_id, replies.offer, users.username, users.rate, users.id, replies.rep_date, replies.status, replies.deadline FROM replies INNER JOIN users ON replies.user_id=users.id WHERE replies.request_id = ? ORDER BY replies.rep_date DESC;', req)

    # Dismiss rejected
    rp = []
    for row in rep:
        if row['status'] != 'rejected':
            rp.append(row)

    return render_template('replies.html', rep=rp, req=req)


@app.route('/myreplies', methods=['GET', 'POST'])
@login_required
def myreplies():
    if request.method == 'POST':
        api_key = os.environ.get('API_KEY')
        rep_id = request.form.get('rep')
        loc = db.execute('SELECT latitude, longitude FROM users WHERE id = ?;', session['user_id'])[0]
        rep = db.execute('SELECT replies.request_id, replies.offer, replies.rep_date, replies.status, replies.details, requests.title, requests.description, requests.request_id, users.username, users.id, users.rate, requests.lat, requests.lng, requests.deadline FROM ((replies INNER JOIN requests ON replies.request_id=requests.request_id) INNER JOIN users ON requests.user_id=users.id) WHERE replies.reply_id = ?;', rep_id)[0]
        rep['distance'] = distance((loc['latitude'], loc['longitude']), (rep['lat'], rep['lng']))
        sss = db.execute('SELECT seen FROM transactions WHERE reply_id = ?;', rep_id)
        seen = 0
        if sss != []:
            seen = sss[0]['seen']

        return render_template('my_reply.html', rep=rep, repid=rep_id, apikey=api_key, seen=seen)

    else:
        rp = db.execute('SELECT replies.reply_id, replies.request_id, replies.offer, replies.rep_date, replies.status, requests.title, users.username, users.id, users.rate, replies.deadline FROM ((replies INNER JOIN requests ON replies.request_id=requests.request_id) INNER JOIN users ON requests.user_id=users.id) WHERE replies.user_id = ?;', session['user_id'])
        return render_template('myreplies.html', rep=rp)


@app.route('/single_rep', methods=['POST'])
@login_required
def single_rep():
    api_key = os.environ.get('API_KEY')
    rep_id = request.form.get('repid')
    reply = db.execute('SELECT replies.request_id, replies.details, replies.offer, users.username, users.rate, users.id, users.votes, replies.rep_date, replies.deadline, replies.status, requests.title, requests.description, requests.lat, requests.lng FROM ((replies INNER JOIN users ON replies.user_id=users.id) INNER JOIN requests ON replies.request_id=requests.request_id) WHERE replies.reply_id = ?;', rep_id)[0]

    return render_template('singlereply.html', rep=reply, repid=rep_id, apikey=api_key)


@app.route('/accept_reply', methods=['POST'])
@login_required
def accept_reply():
    rep_id = request.form.get('repid')
    stat = 'accepted'
    db.execute('UPDATE replies SET status = ? WHERE reply_id = ?;', stat, rep_id)

    reply = db.execute('SELECT replies.request_id, replies.details, replies.offer, users.username, users.rate, users.id, users.votes, replies.rep_date, replies.deadline, replies.status, requests.title, requests.description, requests.lat, requests.lng FROM ((replies INNER JOIN users ON replies.user_id=users.id) INNER JOIN requests ON replies.request_id=requests.request_id) WHERE replies.reply_id = ?;', rep_id)[0]

    return render_template('reply_accepted.html', repid=rep_id, rep=reply)


@app.route('/conversation', methods=['POST'])
@login_required
def conversation():
    rep_id = request.form.get('repid')
    if request.form.get('message'):
        db.execute('INSERT INTO conversations (reply_id, message, sender_id) VALUES (?, ?, ?);', rep_id, request.form.get('message'), session['user_id'])

    req_data = db.execute('SELECT title, user_id FROM requests WHERE request_id IN (SELECT request_id FROM replies WHERE reply_id = ?);', rep_id)[0]

    title = req_data['title']
    req_user = req_data['user_id']
    conv = db.execute('SELECT conversations.message, users.username, conversations.msg_date, conversations.sender_id FROM conversations INNER JOIN users ON conversations.sender_id=users.id WHERE conversations.reply_id = ?;', rep_id)

    return render_template('conversation.html', conv=conv, title=title, user=session['user_id'], repid=rep_id, requser=req_user)


@app.route('/pay_form', methods=['POST'])
@login_required
def comply_pay_form():
    rep_id = request.form.get('repid')
    info = db.execute('SELECT requests.title, requests.request_id, requests.description, replies.offer, replies.details, replies.deadline, users.username, users.id FROM ((replies INNER JOIN users ON replies.user_id=users.id) INNER JOIN requests ON replies.request_id=requests.request_id) WHERE replies.reply_id = ?;', rep_id)[0]
    return render_template('payform.html', repid=rep_id, info=info)


@app.route('/reject_reply', methods=['POST'])
@login_required
def reject_reply():
    rep_id = request.form.get('repid')
    db.execute('UPDATE replies SET status = "rejected" WHERE reply_id = ?', rep_id)
    return redirect('/myrequests')


# Updates information whenever a task is done and the price is payed
@app.route('/comply_pay', methods=['POST'])
@login_required
def comply_pay():
    if not (request.form.get('rate') and request.form.get('offer')):
        return render_template('error.html', errno=400, error='must complete all the obligatory fields', redir='/myreplies')

    rate = int(request.form.get('rate'))
    offer = int(request.form.get('offer'))
    receiver_id = request.form.get('userid')
    req_id = request.form.get('reqid')
    rep_id = request.form.get('repid')
    user_id = session['user_id']

    db.execute('INSERT INTO transactions (amount, sender_id, receiver_id, reply_id) VALUES (?, ?, ?, ?);', offer, user_id, receiver_id, rep_id)

    if request.form.get('comments'):
        db.execute('INSERT INTO comments (content, sender_id, receiver_id) VALUES (?, ?, ?);', request.form.get('comments'), user_id, receiver_id)

    # Calculate new rating and update votes
    rating = db.execute('SELECT rate FROM users WHERE id = ?;', receiver_id)[0]['rate']
    votes = db.execute('SELECT votes FROM users WHERE id = ?;', receiver_id)[0]['votes']
    n_votes = votes + 1

    rat = (rating * float(votes) + rate) / float(n_votes)

    db.execute('UPDATE replies SET status = "completed" WHERE reply_id = ?;', rep_id)
    db.execute('UPDATE requests SET status = TRUE WHERE request_id = ?;', req_id)

    db.execute('UPDATE users SET rate = ?, votes = ? WHERE id = ?;', round(rat, 2), n_votes, receiver_id)

    # Take tokens from payer
    s_tok = db.execute('SELECT tokens FROM users WHERE id = ?;', user_id)[0]['tokens']
    s_bal = s_tok - offer
    db.execute('UPDATE users SET tokens = ? WHERE id = ?;', s_bal, user_id)

    # Give tokens to receiver
    r_tok = db.execute('SELECT tokens FROM users WHERE id = ?;', receiver_id)[0]['tokens']
    r_bal = r_tok + offer
    db.execute('UPDATE users SET tokens = ? WHERE id = ?;', r_bal, receiver_id)

    return redirect('/myrequests')


# Renders the form to rate a requestor who complied a deal
@app.route('/rate_req', methods=['POST'])
@login_required
def rate_requestor():
    user_id = request.form.get('userid')
    rep_id = request.form.get('repid')
    username = db.execute('SELECT username FROM users WHERE id = ?;', user_id)[0]['username']
    rep_info = db.execute('SELECT replies.details, replies.offer, replies.rep_date, requests.title, requests.description FROM replies INNER JOIN requests ON replies.request_id=requests.request_id WHERE replies.reply_id = ?;', rep_id)[0]

    return render_template('rate_req.html', userid=user_id, username=username, repinfo=rep_info, repid=rep_id)


# Gets the information posted by rate_req
@app.route('/rate_post', methods=['POST'])
@login_required
def rate_post():
    receiver_id = request.form.get('userid')
    user_id = session['user_id']
    rep_id = request.form.get('repid')

    if not request.form.get('rate'):
        return render_template('error.html', errno=400, error='rating not received', redir='/myreplies')

    rate = int(request.form.get('rate'))

    if request.form.get('comments'):
        db.execute('INSERT INTO comments (content, sender_id, receiver_id) VALUES (?, ?, ?);', request.form.get('comments'), user_id, receiver_id)

    # Calculate new rating and update votes
    rating = db.execute('SELECT rate FROM users WHERE id = ?;', receiver_id)[0]['rate']
    votes = db.execute('SELECT votes FROM users WHERE id = ?;', receiver_id)[0]['votes']
    n_votes = votes + 1

    rat = (rating * float(votes) + rate) / float(n_votes)

    db.execute('UPDATE users SET rate = ?, votes = ? WHERE id = ?;', round(rat, 2), n_votes, receiver_id)
    db.execute('UPDATE transactions SET seen = TRUE WHERE reply_id = ?;', rep_id)

    return redirect('/myreplies')


@app.route('/delete_reply', methods=['POST'])
@login_required
def del_reply():
    rep_id = request.form.get('repid')
    db.execute('DELETE FROM replies WHERE reply_id = ?;', rep_id)
    return redirect('/myreplies')


@app.route('/help', methods=['GET', 'POST'])
@login_required
def help_someone():
    if request.method == 'POST':
        api_key = os.environ.get('API_KEY')
        help_request = request.form.get('rqst')
        info = db.execute('SELECT * FROM requests WHERE request_id = ?;', help_request)[0]
        user_info = db.execute('SELECT username, rate, votes FROM users WHERE id = ?;', info['user_id'])[0]
        info['username'] = user_info['username']
        info['rate'] = user_info['rate']
        info['votes'] = user_info['votes']

        # Calculate distance
        location = db.execute('SELECT latitude, longitude FROM users WHERE id = ?;', session['user_id'])[0]
        info['distance'] = distance((info['lat'], info['lng']), (location['latitude'], location['longitude']))

        return render_template('request_info.html', info=info, apikey=api_key)

    else:
        reqs = db.execute('SELECT requests.request_id, requests.title, users.username, users.rate, users.id, requests.difficulty, requests.time_elapse, requests.deadline, requests.offer, requests.req_date, requests.category, requests.lat, requests.lng FROM requests INNER JOIN users ON requests.user_id=users.id WHERE NOT requests.user_id = ? AND requests.status = FALSE ORDER BY requests.req_date DESC;', session['user_id'])
        location = db.execute('SELECT latitude, longitude FROM users WHERE id = ?;', session['user_id'])[0]

        # Store distance
        data = []
        for e in reqs:
            row = e
            row['distance'] = distance((e['lat'], e['lng']), (location['latitude'], location['longitude']))
            data.append(row)

        return render_template('help.html', data=data)


@app.route('/reply_form', methods=['POST'])
@login_required
def reply_form():
    api_key = os.environ.get('API_KEY')
    request_id = request.form.get('rqst')
    data = db.execute('SELECT users.username, users.id, requests.title, requests.offer, requests.description, requests.lat, requests.lng, requests.deadline FROM requests INNER JOIN users ON requests.user_id=users.id WHERE requests.request_id = ?;', request_id)[0]
    return render_template('send_reply.html', data=data, apikey=api_key, reqid=request_id)


@app.route('/send_reply', methods=['POST'])
@login_required
def send_reply():
    if not(request.form.get('offer') and request.form.get('details') and request.form.get('reqid') and request.form.get('day') and request.form.get('month') and request.form.get('year')) or not request.form.get('offer').isnumeric():
        return render_template('error.html', errno=505, error='invalid input', redir='/help')

    offer = request.form.get('offer')
    details = request.form.get('details')
    request_id = request.form.get('reqid')

    # Format deadline
    day = ''
    if len(request.form.get('day')) == 1:
        day = '0' + request.form.get('day')
    else:
        day = request.form.get('day')
    deadline = request.form.get('year') + '-' + request.form.get('month') + '-' + day + ' 00:00:00'

    db.execute('INSERT INTO replies (offer, details, deadline, request_id, user_id) VALUES (?, ?, ?, ?, ?);', offer, details, deadline, request_id, session['user_id'])

    return redirect('/myreplies')


@app.route('/user', methods=['POST'])
@login_required
def user():
    user_id = request.form.get('userid')
    user_info = db.execute('SELECT id, username, rate, votes FROM users WHERE id = ?;', user_id)[0]
    data = db.execute('SELECT title, category, difficulty, offer, req_date, deadline, time_elapse, lat, lng, request_id FROM requests WHERE user_id = ?;', user_id)
    loc = db.execute('SELECT latitude, longitude FROM users WHERE id = ?;', session['user_id'])[0]
    dt = []

    for row in data:
        row['distance'] = distance((loc['latitude'], loc['longitude']), (row['lat'], row['lng']))
        dt.append(row)

    cmnts = db.execute('SELECT comments.content, comments.cmnt_date, users.username, users.id FROM comments INNER JOIN users ON comments.sender_id=users.id WHERE comments.receiver_id = ?;', user_id)

    return render_template('user.html', data=dt, userinfo=user_info, cmnts=cmnts)


@app.route('/myprofile')
@login_required
def myprofile():
    api_key = os.environ.get('API_KEY')
    myid = session['user_id']
    myinfo = db.execute('SELECT username, email, tokens, rate, votes, latitude, longitude FROM users WHERE id = ?;', myid)[0]
    myreplies = db.execute('SELECT replies.reply_id, replies.request_id, replies.offer, replies.rep_date, replies.status, requests.title, users.username, users.id, users.rate, replies.deadline FROM ((replies INNER JOIN requests ON replies.request_id=requests.request_id) INNER JOIN users ON requests.user_id=users.id) WHERE replies.user_id = ?;', myid)
    myrequests = db.execute('SELECT title, description, offer, req_date, request_id FROM requests WHERE user_id = ? AND status = FALSE;', myid)

    # Count replies for each request
    data = []
    for row in myrequests:
        row['reps'] = db.execute('SELECT COUNT(reply_id) FROM replies WHERE request_id = ? AND NOT status = "rejected";', row['request_id'])[0]['COUNT(reply_id)']
        data.append(row)

    mycomments = db.execute('SELECT comments.content, comments.cmnt_date, users.username, users.id FROM comments INNER JOIN users ON comments.sender_id=users.id WHERE comments.receiver_id = ?;', myid)

    print(myinfo['latitude'])
    print(myinfo['longitude'])

    return render_template('myprofile.html', apikey=api_key, myinfo=myinfo, myreplies=myreplies, myrequests=data, mycomments=mycomments)


@app.route('/recover', methods=['POST', 'GET'])
def recover():
    if request.method == 'POST':
        return redirect('/') # TODO
    else:
        return render_template('recover.html')


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return render_template('error.html', errno=503, error='internal server error', redir='/')


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)