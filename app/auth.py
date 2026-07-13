import secrets
import string
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user
from .models import db, User

bp = Blueprint("auth", __name__)


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login_investigator", next=request.path))
        if not current_user.is_admin:
            flash("Admin access required for that action.", "error")
            return redirect(url_for("main.index"))
        return view_func(*args, **kwargs)
    return wrapped


def generate_investigator_id():
    last = (User.query.filter(User.investigator_id.isnot(None))
            .order_by(User.id.desc()).first())
    if last and last.investigator_id:
        try:
            next_num = int(last.investigator_id.split("-")[1]) + 1
        except (IndexError, ValueError):
            next_num = User.query.filter_by(role="investigator").count() + 1
    else:
        next_num = 1
    return f"INV-{next_num:05d}"


def generate_temp_password(length=12):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------- LOGIN ----------

@bp.route("/login/admin", methods=["GET", "POST"])
def login_admin():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, role="admin").first()

        if user and user.check_password(password):
            if not user.is_active_user:
                flash("This account has been disabled.", "error")
                return redirect(url_for("auth.login_admin"))
            login_user(user, remember=bool(request.form.get("remember")))
            flash(f"Welcome back, {user.username}.", "success")
            return redirect(request.args.get("next") or url_for("main.index"))

        flash("Invalid admin username or password.", "error")

    return render_template("login_admin.html")


@bp.route("/login/investigator", methods=["GET", "POST"])
def login_investigator():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username, role="investigator").first()

        if user and user.check_password(password):
            if not user.is_active_user:
                flash("This account has been disabled.", "error")
                return redirect(url_for("auth.login_investigator"))
            login_user(user, remember=bool(request.form.get("remember")))
            flash(f"Welcome back, {user.username}.", "success")
            return redirect(request.args.get("next") or url_for("main.index"))

        flash("Invalid investigator username or password.", "error")

    return render_template("login_investigator.html")


# ---------- REGISTER ----------

@bp.route("/register/admin", methods=["GET", "POST"])
def register_admin():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        invite_code = request.form.get("invite_code", "")

        errors = []
        if not username or not email or not password:
            errors.append("All fields are required.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if User.query.filter_by(username=username).first():
            errors.append("That username is already taken.")
        if User.query.filter_by(email=email).first():
            errors.append("That email is already registered.")
        if invite_code != current_app.config.get("ADMIN_INVITE_CODE"):
            errors.append("Invalid admin invite code.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register_admin.html", username=username, email=email)

        user = User(username=username, email=email, role="admin")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Admin account created. Please sign in.", "success")
        return redirect(url_for("auth.login_admin"))

    return render_template("register_admin.html")


@bp.route("/register/investigator", methods=["GET", "POST"])
def register_investigator():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []
        if not username or not email or not password:
            errors.append("All fields are required.")
        if password != confirm:
            errors.append("Passwords do not match.")
        if User.query.filter_by(username=username).first():
            errors.append("That username is already taken.")
        if User.query.filter_by(email=email).first():
            errors.append("That email is already registered.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register_investigator.html", username=username, email=email)

        user = User(
            username=username,
            email=email,
            role="investigator",
            investigator_id=generate_investigator_id()
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash(f"Investigator account created. Your ID is {user.investigator_id}. Please sign in.", "success")
        return redirect(url_for("auth.login_investigator"))

    return render_template("register_investigator.html")


# ---------- LOGOUT ----------

@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("auth.login_investigator"))


# ---------- ADMIN: MANAGE USERS ----------

@bp.route("/admin/users", methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "investigator")
        if not username or not password:
            flash("Username and password are required.", "error")
        elif User.query.filter_by(username=username).first():
            flash(f"Username '{username}' already exists.", "error")
        else:
            user = User(username=username, role=role)
            if role == "investigator":
                user.investigator_id = generate_investigator_id()
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash(f"Account '{username}' created as {role}.", "success")
        return redirect(url_for("auth.manage_users"))
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin_users.html", users=users)


@bp.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == "POST":
        new_role = request.form.get("role", user.role)
        new_password = request.form.get("password", "").strip()

        if new_role == "investigator" and not user.investigator_id:
            user.investigator_id = generate_investigator_id()
        user.role = new_role

        if new_password:
            user.set_password(new_password)

        db.session.commit()
        flash(f"Updated '{user.username}'.", "success")
        return redirect(url_for("auth.manage_users"))

    return render_template("edit_user.html", user=user)


@bp.route("/admin/users/<int:user_id>/reset_password", methods=["POST"])
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    temp_password = generate_temp_password()
    user.set_password(temp_password)
    db.session.commit()
    flash(
        f"Password for '{user.username}' has been reset. "
        f"Temporary password: {temp_password} — share this securely; "
        f"it will not be shown again.",
        "success"
    )
    return redirect(url_for("auth.manage_users"))


@bp.route("/admin/users/<int:user_id>/disable", methods=["POST"])
@admin_required
def disable_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You can't disable your own account.", "error")
    else:
        user.is_active_user = False
        db.session.commit()
        flash(f"'{user.username}' disabled.", "success")
    return redirect(url_for("auth.manage_users"))


@bp.route("/admin/users/<int:user_id>/enable", methods=["POST"])
@admin_required
def enable_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active_user = True
    db.session.commit()
    flash(f"'{user.username}' enabled.", "success")
    return redirect(url_for("auth.manage_users"))


@bp.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You can't delete your own account.", "error")
    else:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        flash(f"'{username}' permanently deleted.", "success")
    return redirect(url_for("auth.manage_users"))
