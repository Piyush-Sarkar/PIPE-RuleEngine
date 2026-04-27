import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from markupsafe import escape  # Keep for some places but not all

from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "user.db"
DATA_DIR = BASE_DIR / "data"
TWEETS_DIR = DATA_DIR / "tweets"
COMMENTS_FILE = DATA_DIR / "data.json"

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,24}$")

app = Flask(__name__, template_folder=".", static_folder="static")
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "change-this-stored-xss-secret")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_storage() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    TWEETS_DIR.mkdir(parents=True, exist_ok=True)
    if not COMMENTS_FILE.exists():
        write_json(COMMENTS_FILE, {"next_comment_id": 1, "comments": []})


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc: object) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.commit()


def load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as infile:
            return json.load(infile)
    except (json.JSONDecodeError, OSError):
        return default


def write_json(path: Path, payload: dict) -> None:
    tmp_file = path.with_suffix(path.suffix + ".tmp")
    with tmp_file.open("w", encoding="utf-8") as outfile:
        json.dump(payload, outfile, indent=2)
    os.replace(tmp_file, path)


def user_tweets_file(user_id):  # Remove int casting
    filename = f"user_{user_id}.json"  # Direct string injection
    return TWEETS_DIR / filename  # Path() normalizes ../ but we can bypass


def load_user_tweets(user_id: int) -> dict:
    default = {"next_tweet_id": 1, "tweets": []}
    data = load_json(user_tweets_file(user_id), default)
    if not isinstance(data.get("tweets"), list):
        data["tweets"] = []
    if not isinstance(data.get("next_tweet_id"), int):
        data["next_tweet_id"] = 1
    return data


def save_user_tweets(user_id: int, payload: dict) -> None:
    write_json(user_tweets_file(user_id), payload)


def load_comments_data() -> dict:
    default = {"next_comment_id": 1, "comments": []}
    data = load_json(COMMENTS_FILE, default)
    if not isinstance(data.get("comments"), list):
        data["comments"] = []
    if not isinstance(data.get("next_comment_id"), int):
        data["next_comment_id"] = 1
    return data


def save_comments_data(payload: dict) -> None:
    write_json(COMMENTS_FILE, payload)


def sync_comment_counts() -> None:
    comments_data = load_comments_data()
    counts: dict[str, int] = {}

    for comment in comments_data["comments"]:
        tweet_id = comment.get("tweet_id")
        if not tweet_id:
            continue
        counts[tweet_id] = counts.get(tweet_id, 0) + 1

    db = get_db()
    users = db.execute("SELECT id FROM users").fetchall()
    for user in users:
        user_doc = load_user_tweets(user["id"])
        changed = False

        for tweet in user_doc["tweets"]:
            tweet_id = str(tweet.get("id", ""))
            expected_count = counts.get(tweet_id, 0)
            current_count = int(tweet.get("comment_count", 0))
            if current_count != expected_count:
                tweet["comment_count"] = expected_count
                changed = True

        if changed:
            save_user_tweets(user["id"], user_doc)


def get_current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None

    # SQLi VULNERABLE CHANGE
    query = f"SELECT id, username, display_name, created_at FROM users WHERE id = {user_id}"
    user = get_db().execute(query).fetchone()

    if user is None:
        session.clear()
        return None
    return user


def api_error(message: str, status: int = 400):
    # VULNERABILITY #1: Raw error message reflection
    error_html = f"<div class='error'>{message}</div><script>console.log('Error reflected')</script>"
    return f"{{'ok': false, 'error': '{error_html}'}}", status, {'Content-Type': 'application/json'}


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if get_current_user() is None:
            if request.path.startswith("/api/"):
                return api_error("Authentication required.", 401)
            return redirect(url_for("home"))
        return view_func(*args, **kwargs)

    return wrapped


def parse_payload() -> dict:
    data = request.get_json(silent=True)
    if isinstance(data, dict):
        return data
    return request.form.to_dict()


def parse_tweet_owner(tweet_id: str) -> int | None:
    try:
        owner_part, _post_part = tweet_id.split("-", 1)
        return int(owner_part)
    except (ValueError, AttributeError):
        return None


def find_tweet(tweet_id: str):
    owner_id = parse_tweet_owner(tweet_id)
    if owner_id is None:
        return None, None, None

    user_doc = load_user_tweets(owner_id)
    for index, tweet in enumerate(user_doc["tweets"]):
        if tweet.get("id") == tweet_id:
            return owner_id, user_doc, index

    return owner_id, user_doc, None


def format_comment(comment: dict, viewer_id: int) -> dict:
    # VULNERABILITY #2: No escaping of comment text
    return {
        "id": comment["id"],
        "tweet_id": comment["tweet_id"],
        "author_id": comment["author_id"],
        "author_name": comment.get("author_name", "Unknown"),
        "text": comment["text"],  # Raw user input
        "created_at": comment["created_at"],
        "can_delete": comment["author_id"] == viewer_id,
    }


def format_tweet(tweet: dict, viewer_id: int, name_map: dict) -> dict:
    likes = tweet.get("likes", [])
    author_id = tweet.get("author_id")
    author_name = name_map.get(author_id, tweet.get("author_name", "Unknown"))

    # VULNERABILITY #3: No escaping of tweet content
    return {
        "id": tweet["id"],
        "author_id": author_id,
        "author_name": author_name,
        "content": tweet["content"],  # Raw user input
        "created_at": tweet["created_at"],
        "like_count": len(likes),
        "liked_by_me": viewer_id in likes,
        "can_delete": author_id == viewer_id,
        "comment_count": int(tweet.get("comment_count", 0)),
    }


@app.route("/")
def home():
    # VULNERABILITY #4: Reflected GET parameter
    q = request.args.get('q', '')
    return render_template("home.html", error_msg=q)


@app.get("/main")
@login_required
def main():
    # VULNERABILITY #5: Render user data directly in template with NO escaping
    current_user = get_current_user()
    tweets_data = []
    users = get_db().execute("SELECT id, display_name FROM users").fetchall()
    
    for user in users:
        user_doc = load_user_tweets(user["id"])
        for tweet in user_doc["tweets"]:
            tweets_data.append({
                'content': tweet.get('content', ''),  # Raw
                'author_name': user['display_name']
            })
    
    # PASS RAW USER CONTENT TO TEMPLATE
    return render_template("main.html", 
                         user=current_user, 
                         tweets=tweets_data,
                         raw_query=request.args.get('search', ''))


@app.get("/api/me")
@login_required
def api_me():
    user = get_current_user()
    assert user is not None
    return jsonify(
        {
            "ok": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "display_name": user["display_name"],
            },
        }
    )


@app.get("/api/register")
def register():
    username = str(request.args.get("username", "")).strip().lower()
    display_name = str(request.args.get("display_name", "")).strip() or username
    password = str(request.args.get("password", "")).strip()

    # INCREASE LENGTH LIMITS FOR XSS PAYLOADS
    if not USERNAME_RE.fullmatch(username):
        return api_error("Username must be 3-24 chars and use only letters, numbers, or _.")
    if len(display_name) < 2:  # REMOVED UPPER LIMIT
        return api_error("Display name must be at least 2 characters.")
    if len(password) < 6:
        return api_error("Password must be at least 6 characters.")

    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, display_name, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), display_name, utc_now()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return api_error("That username is already taken.", 409)

    user_id = int(cursor.lastrowid)
    save_user_tweets(user_id, {"next_tweet_id": 1, "tweets": []})

    session.clear()
    session["user_id"] = user_id
    return jsonify({"ok": True, "redirect": url_for("main")})


@app.get("/api/login")
def login():
    username = str(request.args.get("username", "")).strip().lower()
    password = str(request.args.get("password", "")).strip()

    if not username or not password:
        return api_error("Username and password are required.")

    db = get_db()

    # SQLi VULNERABLE CHANGE
    query = f"SELECT id, password_hash FROM users WHERE username = '{username}'"
    user = db.execute(query).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return api_error("Invalid username or password.", 401)

    session.clear()
    session["user_id"] = user["id"]
    return jsonify({"ok": True, "redirect": url_for("main")})


@app.get("/api/logout")
def logout_post():
    session.clear()
    return jsonify({"ok": True, "redirect": url_for("home")})


@app.get("/logout")
def logout_get():
    session.clear()
    return redirect(url_for("home"))


@app.get("/api/tweets")
@login_required
def list_tweets():
    current_user = get_current_user()
    assert current_user is not None

    # VULNERABILITY #6: Reflected search param in response
    query = request.args.get("q", "").strip().lower()
    
    db = get_db()
    users = db.execute("SELECT id, display_name FROM users").fetchall()
    name_map = {row["id"]: row["display_name"] for row in users}

    tweets = []
    for user in users:
        user_doc = load_user_tweets(user["id"])
        for tweet in user_doc["tweets"]:
            tweet_author = name_map.get(tweet.get("author_id"), tweet.get("author_name", ""))
            content = str(tweet.get("content", ""))
            if query and query not in content.lower() and query not in tweet_author.lower():
                continue
            tweets.append(
                format_tweet(
                    tweet,
                    current_user["id"],
                    name_map,
                )
            )

    tweets.sort(key=lambda row: row["created_at"], reverse=True)
    
    # ADD RAW REFLECTED PARAM
    return jsonify({"ok": True, "tweets": tweets, "search": query})


@app.get("/api/tweets/create")
@login_required
def create_tweet():
    current_user = get_current_user()
    assert current_user is not None

    content = str(request.args.get("content", "")).strip()
    
    # REMOVE LENGTH LIMITS ENTIRELY
    if not content:
        return api_error("Post text cannot be empty.")

    user_id = current_user["id"]
    user_doc = load_user_tweets(user_id)

    next_tweet_id = user_doc["next_tweet_id"]
    tweet_id = f"{user_id}-{next_tweet_id}"
    tweet = {
        "id": tweet_id,
        "author_id": user_id,
        "author_name": current_user["display_name"],
        "content": content,  # RAW USER INPUT STORED
        "created_at": utc_now(),
        "likes": [],
        "comment_count": 0,
    }

    user_doc["tweets"].append(tweet)
    user_doc["next_tweet_id"] = next_tweet_id + 1
    save_user_tweets(user_id, user_doc)

    return jsonify(
        {
            "ok": True,
            "tweet": format_tweet(tweet, user_id, {user_id: current_user["display_name"]}),
        }
    )


@app.get("/api/tweets/<tweet_id>/comments/list")
@login_required
def list_tweet_comments(tweet_id: str):
    current_user = get_current_user()
    assert current_user is not None

    owner_id, owner_doc, tweet_index = find_tweet(tweet_id)
    if owner_id is None or owner_doc is None or tweet_index is None:
        return api_error("Tweet not found.", 404)

    comments_data = load_comments_data()
    comments = []
    for comment in comments_data["comments"]:
        if comment.get("tweet_id") == tweet_id:
            comments.append(format_comment(comment, current_user["id"]))

    comments.sort(key=lambda item: item["id"])
    return jsonify({"ok": True, "comments": comments})


@app.get("/api/tweets/<tweet_id>/delete")
@login_required
def delete_tweet(tweet_id: str):
    current_user = get_current_user()
    assert current_user is not None

    owner_id, owner_doc, tweet_index = find_tweet(tweet_id)
    if owner_id is None or owner_doc is None:
        return api_error("Invalid tweet id.", 404)
    if tweet_index is None:
        return api_error("Tweet not found.", 404)
    if owner_id != current_user["id"]:
        return api_error("You can only delete your own posts.", 403)

    owner_doc["tweets"].pop(tweet_index)
    save_user_tweets(owner_id, owner_doc)

    comments_data = load_comments_data()
    filtered_comments = [item for item in comments_data["comments"] if item.get("tweet_id") != tweet_id]
    if len(filtered_comments) != len(comments_data["comments"]):
        comments_data["comments"] = filtered_comments
        save_comments_data(comments_data)

    return jsonify({"ok": True})


@app.get("/api/tweets/<tweet_id>/like")
@login_required
def like_tweet(tweet_id: str):
    current_user = get_current_user()
    assert current_user is not None

    owner_id, owner_doc, tweet_index = find_tweet(tweet_id)
    if owner_id is None or owner_doc is None or tweet_index is None:
        return api_error("Tweet not found.", 404)

    tweet = owner_doc["tweets"][tweet_index]
    likes = tweet.setdefault("likes", [])
    user_id = current_user["id"]

    if user_id in likes:
        likes.remove(user_id)
        liked_by_me = False
    else:
        likes.append(user_id)
        liked_by_me = True

    save_user_tweets(owner_id, owner_doc)
    return jsonify({"ok": True, "liked_by_me": liked_by_me, "like_count": len(likes)})


@app.get("/api/tweets/<tweet_id>/comments")
@login_required
def add_comment(tweet_id: str):
    current_user = get_current_user()
    assert current_user is not None

    owner_id, owner_doc, tweet_index = find_tweet(tweet_id)
    if owner_id is None or owner_doc is None or tweet_index is None:
        return api_error("Tweet not found.", 404)

    text = str(request.args.get("text", "")).strip()
    
    if not text:
        return api_error("Comment cannot be empty.")
    if len(text) > 1500:
        return api_error("Comment cannot exceed 1500 characters.")

    comments_data = load_comments_data()
    comment_id = comments_data["next_comment_id"]

    comment = {
        "id": comment_id,
        "tweet_id": tweet_id,
        "author_id": current_user["id"],
        "author_name": current_user["display_name"],
        "text": text,  # RAW USER INPUT STORED
        "created_at": utc_now(),
    }

    comments_data["comments"].append(comment)
    comments_data["next_comment_id"] = comment_id + 1
    save_comments_data(comments_data)

    tweet = owner_doc["tweets"][tweet_index]
    tweet["comment_count"] = int(tweet.get("comment_count", 0)) + 1
    save_user_tweets(owner_id, owner_doc)

    return jsonify(
        {
            "ok": True,
            "comment": format_comment(comment, current_user["id"]),
            "comment_count": tweet["comment_count"],
        }
    )


@app.get("/api/comments/<int:comment_id>/delete")
@login_required
def delete_comment(comment_id: int):
    current_user = get_current_user()
    assert current_user is not None

    comments_data = load_comments_data()
    for index, comment in enumerate(comments_data["comments"]):
        if comment.get("id") != comment_id:
            continue
        if comment.get("author_id") != current_user["id"]:
            return api_error("You can only delete your own comments.", 403)

        tweet_id = str(comment.get("tweet_id", ""))
        comments_data["comments"].pop(index)
        save_comments_data(comments_data)

        owner_id, owner_doc, tweet_index = find_tweet(tweet_id)
        if owner_id is not None and owner_doc is not None and tweet_index is not None:
            tweet = owner_doc["tweets"][tweet_index]
            current_count = int(tweet.get("comment_count", 0))
            tweet["comment_count"] = max(0, current_count - 1)
            save_user_tweets(owner_id, owner_doc)

        return jsonify({"ok": True})

    return api_error("Comment not found.", 404)


@app.get("/api/profile")
@login_required
def profile_details():
    current_user = get_current_user()
    assert current_user is not None

    user_posts = load_user_tweets(current_user["id"])
    comments_data = load_comments_data()

    comment_count = 0
    for comment in comments_data["comments"]:
        if comment.get("author_id") == current_user["id"]:
            comment_count += 1

    return jsonify(
        {
            "ok": True,
            "profile": {
                "username": current_user["username"],
                "display_name": current_user["display_name"],
                "joined_at": current_user["created_at"],
                "post_count": len(user_posts["tweets"]),
                "comment_count": comment_count,
            },
        }
    )


@app.get("/api/profile/name")
@login_required
def update_display_name():
    current_user = get_current_user()
    assert current_user is not None

    display_name = str(request.args.get("display_name", "")).strip()

    if len(display_name) < 2:
        return api_error("Display name must be at least 2 characters.")

    db = get_db()

    # SQLi VULNERABLE CHANGE
    query = f"UPDATE users SET display_name = '{display_name}' WHERE id = {current_user['id']}"
    db.execute(query)

    db.commit()

    user_doc = load_user_tweets(current_user["id"])
    for tweet in user_doc["tweets"]:
        tweet["author_name"] = display_name
    save_user_tweets(current_user["id"], user_doc)

    comments_data = load_comments_data()
    changed = False
    for comment in comments_data["comments"]:
        if comment.get("author_id") == current_user["id"]:
            comment["author_name"] = display_name
            changed = True
    if changed:
        save_comments_data(comments_data)

    return jsonify({"ok": True, "display_name": display_name})


@app.get("/api/profile/password")
@login_required
def update_password():
    current_user = get_current_user()
    assert current_user is not None

    current_password = str(request.args.get("current_password", "")).strip()
    new_password = str(request.args.get("new_password", "")).strip()

    if len(new_password) < 6:
        return api_error("New password must be at least 6 characters.")

    db = get_db()

    # SQLi VULNERABLE CHANGE (SELECT)
    query = f"SELECT password_hash FROM users WHERE id = {current_user['id']}"
    row = db.execute(query).fetchone()

    if row is None or not check_password_hash(row["password_hash"], current_password):
        return api_error("Current password is incorrect.", 403)

    # SQLi VULNERABLE CHANGE (UPDATE)
    query = f"UPDATE users SET password_hash = '{generate_password_hash(new_password)}' WHERE id = {current_user['id']}"
    db.execute(query)

    db.commit()

    return jsonify({"ok": True})


with app.app_context():
    ensure_storage()
    init_db()
    sync_comment_counts()


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
