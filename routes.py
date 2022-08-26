import os
import json
import random
import binascii
import requests
import datetime as dt

from main import create_app, db, login_manager, csrf
from functools import wraps
from flask import render_template, url_for, redirect, flash, request, abort, jsonify
from flask_login import login_user, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFError
from forms import LoginForm, RegisterForm, FindMovieForm
from models import User, Movie

MOVIE_DB_SEARCH_URL = "https://api.themoviedb.org/3/search/movie"
MOVIE_DB_INFO_URL = "https://api.themoviedb.org/3/movie"
MOVIE_DB_IMAGE_URL = "https://image.tmdb.org/t/p/original"
YOUTUBE_URL = "https://www.youtube.com/embed/"
GEOLOCATION_DB_URL = "https://geolocation-db.com/jsonp/"
MOVIE_DB_API_KEY = os.environ.get('MOVIE_DB_API_KEY')
ROWS_PER_PAGE = 24
title_query = ""

parameters = {
    "api_key": MOVIE_DB_API_KEY,
    "query": title_query
}
params = {
    'api_key': MOVIE_DB_API_KEY
}
headers = {"content-type": "text"}

# Create an application instance
app = create_app()


def insert_db(org_id, title, release_date, runtime, tagline, overview, vote_average, vote_count, genres,
              original_language, poster_path, backdrop_path):
    my_date = dt.datetime.strptime(release_date, "%Y-%m-%d").year
    url = f"{MOVIE_DB_IMAGE_URL}{poster_path}"
    my_movie = Movie(org_id=org_id, title=title, release_date=my_date, runtime=runtime, tagline=tagline,
                     overview=overview, vote_average=vote_average, ranking=vote_count, genres=genres,
                     original_language=original_language, poster_path=url, backdrop_path=backdrop_path)
    db.session.add(my_movie)
    db.session.commit()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id != 1:
                return abort(404)
        else:
            return abort(404)
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.template_filter('datetime_format')
def datetime_format(value):
    return dt.datetime.strptime(value, "%Y-%m-%d").strftime("%d %b, %Y")


@app.template_filter('decimal_places')
def cut_decimal(value):
    res = "{:.1f}".format(value)
    return res


# app name
@app.errorhandler(404)
# inbuilt function which takes error as parameter
def not_found(errmsg):
    # defining function
    return render_template("404.html", errmsg=errmsg)


@app.context_processor
def inject_now():
    return {'now': dt.datetime.utcnow()}


@app.after_request
def apply_caching(response):
    response.headers["HTTP-HEADER"] = "VALUE"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # response.headers["Content-Security-Policy"] = "default-src 'self'; image-src 'self'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'  # includeSubDomains
    return response


# Functions
def generate_secret_key():
    # Cookies Protection
    # Generates a random 24 bit string
    secret_key_value = os.urandom(24)
    # Create the hex-encoded string value.
    secret_key_value_hex_encoded = binascii.hexlify(secret_key_value)
    return secret_key_value_hex_encoded


def get_video_key(video_id: str) -> str:
    get_videos = requests.get(url=f"{MOVIE_DB_INFO_URL}/{video_id}/videos", params=params, headers=headers)
    return get_videos.json()['results'][:1]


def random_number_fun(data: list) -> list:
    _index = random.randint(1, len(data))
    return data[_index - 1]['poster_path']


ip_ban_list = ['127.0.0.1']
current_date = dt.datetime.now()
count_nums = 0
country_code = ""


@app.before_request
def block_method():
    # ip = request.environ.get('REMOTE_ADDR')
    ip = request.remote_addr
    # if ip in ip_ban_list:
    #     abort(403)
    any_function()
    try:
        if count_nums == 1:
            file = open("data.txt", "a")
            file.write(ip + " " + str(current_date) + "\n")
            file.close()
            # geolocation_get(ip)
    except FileNotFoundError:
        file = open("data.txt", "w")
        file.write(ip + " " + str(current_date) + "\n")
        file.close()
        # geolocation_get(ip)


def any_function():
    global count_nums
    count_nums += 1


def geolocation_get(ip_address):
    request_url = GEOLOCATION_DB_URL + ip_address
    response = requests.get(request_url)
    result = response.content.decode()
    result = result.split("(")[1].strip(")")
    result = json.loads(result)
    block_country = result['country_code']
    if str(block_country) == 'MM':
        # if ip_address in ip_ban_list:
        abort(403)


@csrf.exempt
@app.route('/', methods=['GET'], strict_slashes=False)
def index():
    ip = request.remote_addr
    geolocation_get(ip)
    if request.method == 'GET':
        # do for try catch
        all_movie = Movie.query.order_by(Movie.id.desc()).limit(6)

        res_upcoming = requests.get(url=f"{MOVIE_DB_INFO_URL}/upcoming", params=params, headers=headers)
        print(res_upcoming)
        up_coming = res_upcoming.json()['results'][:12]

        res_popular = requests.get(url=f"{MOVIE_DB_INFO_URL}/popular", params=params, headers=headers)
        popular_movie = res_popular.json()['results'][:12]

        res_now_playing = requests.get(url=f"{MOVIE_DB_INFO_URL}/now_playing", params=params, headers=headers)
        now_playing = res_now_playing.json()['results'][:6]

        # we will convert or dump a Python Dictionary to JSON String
        # jsonString = json.dumps(upcoming['results'])
        # with open("upcoming.json", mode="w") as file:
        #     file.write(jsonString)
        return render_template('index.html', current_user=current_user, all_movie=all_movie, upcoming=up_coming,
                               popular=popular_movie, now_playing=now_playing, img_url=MOVIE_DB_IMAGE_URL)


@csrf.exempt
@app.route('/favorite', methods=['GET'])
def favorite():
    page = request.args.get('page', 1, type=int)
    if request.method == 'GET':
        all_movie = Movie.query.paginate(page=page, per_page=ROWS_PER_PAGE)
        # print(type(all_movie))
        # result = movies_schema.dump(all_movie.items)
        # return jsonify(result) or jsonify(result.data)
        if len(all_movie.items) > 0:
            # _index = random.randint(1, len(all_movie.items))
            # random_backdrop_path = all_movie.items[_index - 1].backdrop_path
            return render_template('favorite.html', current_user=current_user, all_movie=all_movie)
        return redirect(url_for('index'))
    return redirect(url_for('index'))


@csrf.exempt
@app.route('/upcoming', methods=['GET'])
def upcoming():
    if request.method == 'GET':
        res_upcoming = requests.get(url=f"{MOVIE_DB_INFO_URL}/upcoming", params=params,
                                    headers=headers)
        up_coming = res_upcoming.json()['results']
        if len(up_coming) > 0:
            # random_backdrop_path = f"{MOVIE_DB_IMAGE_URL}{random_number_fun(up_coming)}"
            return render_template('upcoming.html', current_user=current_user, all_movie=up_coming, is_upcoming=True,
                                   img_url=MOVIE_DB_IMAGE_URL)
        return redirect(url_for('index'))
    return redirect(url_for('index'))


@csrf.exempt
@app.route('/popular', methods=['GET'])
def popular():
    if request.method == 'GET':
        res_popular = requests.get(url=f"{MOVIE_DB_INFO_URL}/popular", params=params, headers=headers)
        populars = res_popular.json()['results']
        if len(populars) > 0:
            # random_backdrop_path = f"{MOVIE_DB_IMAGE_URL}{random_number_fun(populars)}"
            return render_template('popular.html', current_user=current_user, all_movie=populars, is_popular=True,
                                   img_url=MOVIE_DB_IMAGE_URL)
        return redirect(url_for('index'))
    return redirect(url_for('index'))


@csrf.exempt
@app.route('/details/<int:id>', methods=['GET'])
def details(id):
    if request.method == 'GET':
        if id is not None:
            res_detail = requests.get(url=f"{MOVIE_DB_INFO_URL}/{id}", params=params, headers=headers)
            detail = res_detail.json()
            videos = get_video_key(id)
            get_img = requests.get(url=f"{MOVIE_DB_INFO_URL}/{id}/images", params=params, headers=headers)
            backdrops = get_img.json()['backdrops'][:6]
            return render_template('details.html', movie_detail=detail, img_url=MOVIE_DB_IMAGE_URL, videos=videos,
                                   back_drops=backdrops, youtube_url=YOUTUBE_URL)
    return render_template('index.html')


@csrf.exempt
@app.route('/register', methods=['GET', 'POST'])
@admin_only
def register():
    form = RegisterForm()
    # if current_user.is_authenticated:
    #     if current_user.id == 1:
    #         return redirect(url_for('dashboard'))
    #     else:
    #         return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')
        repeat_password = request.form.get('repeat_password')
        user = User.query.filter_by(email=request.form.get('email')).first()
        if len(name) <= 3:
            flash("Name must be 4 characters.")
            return redirect(url_for('register'))
        elif len(password) <= 5:
            flash('Password must contain at least 6 characters.')
            return redirect(url_for('register'))
        elif password != repeat_password:
            flash("Passwords don't match!")
            return redirect(url_for('register'))
        elif user:
            flash('User already exists. Please Log in.')
            return redirect(url_for('register'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method="pbkdf2:sha256",
            salt_length=8
        )
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Successfully registered.")
        return redirect(url_for('register'))
    return render_template('register.html', current_user=current_user, form=form)


@csrf.exempt
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        if current_user.id == 1:
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Login failed, please try again!", 'error')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Login failed, please try again!", 'error')
            return redirect(url_for('login'))
        else:
            login_user(user)
            if user.id == 1:
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('index'))
    return render_template('login.html', form=form)


@csrf.exempt
@app.route('/dashboard', methods=['GET', 'POST'])
@admin_only
def dashboard():
    form = FindMovieForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            res = requests.get(url=MOVIE_DB_SEARCH_URL,
                               params={"api_key": MOVIE_DB_API_KEY, "query": request.form['movie_title']},
                               headers=headers)
            movie_data = res.json()['results']
            return render_template('dashboard.html', form=form, current_user=current_user, is_data=True,
                                   movie_data=movie_data)

    if request.args.get('id') is not None:
        org_id = request.args.get('id')
        res = requests.get(url=f"{MOVIE_DB_INFO_URL}/{org_id}", params=params,
                           headers=headers).json()
        movie_data = Movie.query.filter_by(org_id=org_id).first()
        if movie_data is None:
            insert_db(org_id, res['title'], res['release_date'], res['runtime'], res['tagline'], res['overview'],
                      res['vote_average'], res['vote_count'], res['genres'][0]['name'],
                      res['original_language'], res['poster_path'], res['backdrop_path'])
            flash(f"{res['title']} | successfully save")
        else:
            flash(f"This movie '{movie_data.title}' already exit!!")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', form=form, current_user=current_user)


@csrf.exempt
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({"error": e.description}), 400


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
