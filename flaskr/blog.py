from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for,jsonify
)
from werkzeug.exceptions import abort

from flaskr.auth import login_required
from flaskr.db import get_db

bp = Blueprint('blog', __name__)
@bp.route('/')
def index():
    db = get_db()
    posts = db.execute(
        'SELECT p.id, title, body, created, author_id, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    return jsonify([dict(post) for post in posts]), 200

@bp.route('/create', methods=('POST',))
@login_required
def create():
        data = request.get_json()
        title = data.get('title')
        body = data.get('body')
        error = None

        if not title:
            return jsonify({"error": "Title is required."}), 400
        db = get_db()
        db.execute(
            'INSERT INTO post (title, body, author_id)'
            ' VALUES (?, ?, ?)',
            (title, body, g.user['id'])
        )
        db.commit()
        return jsonify({"message": "Post created successfully."}), 201


def get_post(id, check_author=True):
    post = get_db().execute(
        'SELECT p.id, title, body, created, author_id, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' WHERE p.id = ?',
        (id,)
    ).fetchone()

    if post is None:
        abort(404, f"Post id {id} doesn't exist.")

    if check_author and post['author_id'] != g.user['id']:
        abort(403)

    return post

@bp.route('/<int:id>/update', methods=('PUT',))
@login_required
def update(id):
    post = get_post(id)
    data = request.get_json()
    title = data.get('title')
    body = data.get('body')

    if not title:
        return jsonify({"error": "Title is required."}), 400

    db = get_db()
    db.execute(
        'UPDATE post SET title = ?, body = ? WHERE id = ?',
        (title, body, id)
    )
    db.commit()
    return jsonify({"message": "Post updated successfully."}), 200



@bp.route('/<int:id>/delete', methods=('DELETE',))
@login_required
def delete(id):
    get_post(id)  # Check if the post exists and if the user has permissions.
    db = get_db()
    db.execute('DELETE FROM post WHERE id = ?', (id,))
    db.commit()
    return jsonify({"message": "Post deleted successfully."}), 200