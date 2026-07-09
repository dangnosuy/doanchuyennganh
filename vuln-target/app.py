import os
import json
import hashlib
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, make_response, g
)

DB_PATH = os.environ.get("DB_PATH", "/data/techshop.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "ts-x9k2m7p4q1w8e3r6y0u5i")
INTERNAL_API_KEY = os.environ.get("INTERNAL_API_KEY", "sk-internal-9f3c2a7b1e4d8f6a0c5b")
PAYMENT_GATEWAY_KEY = os.environ.get("PAYMENT_GATEWAY_KEY", "pgw-live-4e2a8c1f9b3d7e5c0a6b")

app = Flask(__name__)
app.secret_key = SECRET_KEY


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        role_cookie = request.cookies.get("role")
        if role_cookie == "admin":
            return f(*args, **kwargs)
        if session.get("role") == "admin":
            return f(*args, **kwargs)
        return redirect(url_for("index"))
    return decorated


# ---------- helpers ----------

def get_cart():
    return session.get("cart", {})


def save_cart(cart):
    session["cart"] = cart


def cart_items_detail(cart):
    if not cart:
        return [], 0
    db = get_db()
    items = []
    total = 0
    for pid, qty in cart.items():
        row = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if row:
            subtotal = row["price"] * qty
            total += subtotal
            items.append({"product": dict(row), "qty": qty, "subtotal": subtotal})
    return items, total


# ---------- public routes ----------

@app.route("/")
def index():
    db = get_db()
    featured = db.execute("SELECT * FROM products WHERE featured=1 LIMIT 8").fetchall()
    categories = db.execute("SELECT DISTINCT category FROM products").fetchall()
    return render_template("index.html", featured=featured, categories=categories)


@app.route("/products")
def products():
    db = get_db()
    cat = request.args.get("category", "")
    if cat:
        prods = db.execute("SELECT * FROM products WHERE category=?", (cat,)).fetchall()
    else:
        prods = db.execute("SELECT * FROM products").fetchall()
    categories = db.execute("SELECT DISTINCT category FROM products").fetchall()
    return render_template("products.html", products=prods, categories=categories, current_cat=cat)


@app.route("/product/<int:pid>")
def product_detail(pid):
    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not product:
        return render_template("404.html"), 404
    related = db.execute(
        "SELECT * FROM products WHERE category=? AND id!=? LIMIT 4",
        (product["category"], pid)
    ).fetchall()
    return render_template("product_detail.html", product=product, related=related)


# ---------- auth ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, md5(password))
        ).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            resp = make_response(redirect(request.args.get("next") or url_for("index")))
            resp.set_cookie("role", user["role"], httponly=False)
            resp.set_cookie("user_id", str(user["id"]), httponly=False)
            return resp
        error = "Tên đăng nhập hoặc mật khẩu không đúng."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("role")
    resp.delete_cookie("user_id")
    return resp


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        full_name = request.form.get("full_name", "").strip()
        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username=? OR email=?", (username, email)
        ).fetchone()
        if existing:
            error = "Tên đăng nhập hoặc email đã tồn tại."
        else:
            db.execute(
                "INSERT INTO users (username, email, password, role, balance, points, full_name, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (username, email, md5(password), "user", 0.0, 0, full_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            )
            db.commit()
            return redirect(url_for("login"))
    return render_template("register.html", error=error)


# ---------- cart ----------

@app.route("/cart")
@login_required
def cart():
    items, total = cart_items_detail(get_cart())
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/add", methods=["POST"])
@login_required
def cart_add():
    pid = str(request.form.get("product_id", ""))
    qty = int(request.form.get("qty", 1))
    cart = get_cart()
    cart[pid] = cart.get(pid, 0) + qty
    save_cart(cart)
    return redirect(request.referrer or url_for("cart"))


@app.route("/cart/remove", methods=["POST"])
@login_required
def cart_remove():
    pid = str(request.form.get("product_id", ""))
    cart = get_cart()
    cart.pop(pid, None)
    save_cart(cart)
    return redirect(url_for("cart"))


@app.route("/cart/coupon", methods=["POST"])
@login_required
def cart_coupon():
    code = request.form.get("coupon", "").strip().upper()
    discount = 0
    message = ""
    db = get_db()

    valid_coupons = {
        "SAVE20": {"type": "percent", "value": 20, "tracked": False},
        "WELCOME50": {"type": "flat", "value": 50000, "tracked": True},
        "TECH100": {"type": "flat", "value": 100000, "tracked": True},
    }

    if code in valid_coupons:
        coupon = valid_coupons[code]
        if coupon["tracked"]:
            usage = db.execute(
                "SELECT id FROM coupon_usage WHERE user_id=? AND coupon_code=?",
                (session["user_id"], code)
            ).fetchone()
            if usage:
                message = "Bạn đã sử dụng mã giảm giá này rồi."
            else:
                db.execute(
                    "INSERT INTO coupon_usage (user_id, coupon_code, used_at) VALUES (?,?,?)",
                    (session["user_id"], code, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
                db.commit()
                session["coupon"] = {"code": code, "type": coupon["type"], "value": coupon["value"]}
                message = f"Áp dụng mã thành công!"
        else:
            session["coupon"] = {"code": code, "type": coupon["type"], "value": coupon["value"]}
            message = f"Áp dụng mã thành công!"
    else:
        message = "Mã giảm giá không hợp lệ."

    return redirect(url_for("cart"))


# ---------- checkout ----------

@app.route("/checkout")
@login_required
def checkout():
    cart = get_cart()
    if not cart:
        return redirect(url_for("cart"))
    db = get_db()
    items, total = cart_items_detail(cart)
    coupon = session.get("coupon")
    discount = 0
    if coupon:
        if coupon["type"] == "percent":
            discount = total * coupon["value"] / 100
        else:
            discount = coupon["value"]
    final_total = total - discount
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("checkout.html", items=items, total=total,
                           discount=discount, final_total=final_total,
                           coupon=coupon, user=user)


@app.route("/checkout/confirm", methods=["POST"])
@login_required
def checkout_confirm():
    db = get_db()
    cart = get_cart()
    if not cart:
        return redirect(url_for("cart"))

    address = request.form.get("address", "")
    client_total = request.form.get("total", "0")

    try:
        total = float(client_total)
    except ValueError:
        total = 0.0

    items_snapshot = []
    for pid, qty in cart.items():
        prod = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
        if prod:
            client_price = request.form.get(f"price_{pid}", str(prod["price"]))
            try:
                unit_price = float(client_price)
            except ValueError:
                unit_price = prod["price"]
            items_snapshot.append({
                "product_id": int(pid),
                "name": prod["name"],
                "price": unit_price,
                "qty": qty
            })

    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

    if total < 0:
        new_balance = user["balance"] + abs(total)
        db.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, session["user_id"]))
        total = 0.0

    db.execute(
        "INSERT INTO orders (user_id, total, status, address, items, created_at) VALUES (?,?,?,?,?,?)",
        (session["user_id"], total, "pending", address,
         json.dumps(items_snapshot), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    db.commit()
    order_id = db.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

    points_earned = int(total / 10000)
    db.execute("UPDATE users SET points=points+? WHERE id=?", (points_earned, session["user_id"]))
    db.commit()

    save_cart({})
    session.pop("coupon", None)
    return redirect(url_for("checkout_success", order_id=order_id))


@app.route("/checkout/success/<int:order_id>")
@login_required
def checkout_success(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    return render_template("checkout_success.html", order=order)


# ---------- orders ----------

@app.route("/orders")
@login_required
def orders():
    db = get_db()
    user_orders = db.execute(
        "SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template("orders.html", orders=user_orders)


@app.route("/orders/<int:order_id>")
@login_required
def order_detail(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        return render_template("404.html"), 404
    items = json.loads(order["items"])
    user = db.execute("SELECT username FROM users WHERE id=?", (order["user_id"],)).fetchone()
    return render_template("order_detail.html", order=order, items=items, owner=user)


# ---------- profile ----------

@app.route("/profile")
@login_required
def profile_redirect():
    return redirect(url_for("profile", user_id=session["user_id"]))


@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        return render_template("404.html"), 404
    return render_template("profile.html", user=user)


@app.route("/profile/edit", methods=["POST"])
@login_required
def profile_edit():
    db = get_db()
    full_name = request.form.get("full_name", "")
    phone = request.form.get("phone", "")
    address = request.form.get("address", "")
    role = request.form.get("role", None)

    if role:
        db.execute(
            "UPDATE users SET full_name=?, phone=?, address=?, role=? WHERE id=?",
            (full_name, phone, address, role, session["user_id"])
        )
        session["role"] = role
    else:
        db.execute(
            "UPDATE users SET full_name=?, phone=?, address=? WHERE id=?",
            (full_name, phone, address, session["user_id"])
        )
    db.commit()
    return redirect(url_for("profile", user_id=session["user_id"]))


# ---------- transfer points ----------

@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    db = get_db()
    message = None
    error = None
    if request.method == "POST":
        to_username = request.form.get("to_username", "").strip()
        try:
            amount = int(request.form.get("amount", "0"))
        except ValueError:
            amount = 0

        sender = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        recipient = db.execute("SELECT * FROM users WHERE username=?", (to_username,)).fetchone()

        if not recipient:
            error = "Người dùng không tồn tại."
        elif recipient["id"] == session["user_id"]:
            error = "Không thể chuyển điểm cho chính mình."
        elif sender["points"] < amount:
            error = "Số điểm không đủ."
        else:
            db.execute("UPDATE users SET points=points-? WHERE id=?", (amount, session["user_id"]))
            db.execute("UPDATE users SET points=points+? WHERE id=?", (amount, recipient["id"]))
            db.commit()
            message = f"Chuyển thành công {amount} điểm cho {to_username}."

        sender = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        return render_template("transfer.html", message=message, error=error, user=sender)

    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template("transfer.html", user=user)


# ---------- admin ----------

@app.route("/admin")
def admin_dashboard():
    role_cookie = request.cookies.get("role")
    if role_cookie != "admin" and session.get("role") != "admin":
        return redirect(url_for("login"))
    db = get_db()
    stats = {
        "users": db.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"],
        "orders": db.execute("SELECT COUNT(*) as c FROM orders").fetchone()["c"],
        "products": db.execute("SELECT COUNT(*) as c FROM products").fetchone()["c"],
        "revenue": db.execute("SELECT SUM(total) as s FROM orders WHERE status='delivered'").fetchone()["s"] or 0,
    }
    recent_orders = db.execute(
        "SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id=u.id ORDER BY o.created_at DESC LIMIT 10"
    ).fetchall()
    return render_template("admin/dashboard.html", stats=stats, recent_orders=recent_orders)


@app.route("/admin/users")
@admin_required
def admin_users():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/delete", methods=["POST"])
@admin_required
def admin_users_delete_post():
    db = get_db()
    user_id = request.form.get("user_id")
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    return redirect(url_for("admin_users"))


@app.route("/admin/users/delete", methods=["GET"])
@login_required
def admin_users_delete_get():
    db = get_db()
    user_id = request.args.get("user_id")
    if user_id:
        db.execute("DELETE FROM users WHERE id=?", (user_id,))
        db.commit()
    return redirect(url_for("admin_users"))


@app.route("/admin/users/promote", methods=["POST"])
@admin_required
def admin_users_promote():
    db = get_db()
    user_id = request.form.get("user_id")
    new_role = request.form.get("role", "user")
    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
    db.commit()
    return redirect(url_for("admin_users"))


@app.route("/admin/orders")
@admin_required
def admin_orders():
    db = get_db()
    orders = db.execute(
        "SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id=u.id ORDER BY o.created_at DESC"
    ).fetchall()
    return render_template("admin/orders.html", orders=orders)


# ---------- API v1 (no auth) ----------

@app.route("/api/v1/users")
def api_v1_users():
    db = get_db()
    users = db.execute("SELECT id, username, email, role, balance, points, full_name, phone, address, created_at FROM users").fetchall()
    return jsonify([dict(u) for u in users])


@app.route("/api/v1/products")
def api_v1_products():
    db = get_db()
    prods = db.execute("SELECT * FROM products").fetchall()
    return jsonify([dict(p) for p in prods])


@app.route("/api/v1/orders/<int:order_id>")
def api_v1_order(order_id):
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if not order:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(order))


# ---------- API v2 (auth required) ----------

def api_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            token = request.headers.get("Authorization", "")
            if not token:
                return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/api/v2/users")
@api_auth_required
def api_v2_users():
    db = get_db()
    users = db.execute("SELECT id, username, email, role, created_at FROM users").fetchall()
    return jsonify([dict(u) for u in users])


@app.route("/api/v2/me", methods=["GET", "PATCH"])
@api_auth_required
def api_v2_me():
    db = get_db()
    if request.method == "GET":
        user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        if not user:
            return jsonify({"error": "Not found"}), 404
        return jsonify(dict(user))

    data = request.get_json(force=True, silent=True) or {}
    allowed = ["full_name", "phone", "address", "email", "role"]
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({"error": "No valid fields"}), 400

    set_clause = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [session["user_id"]]
    db.execute(f"UPDATE users SET {set_clause} WHERE id=?", values)
    db.commit()

    if "role" in updates:
        session["role"] = updates["role"]

    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return jsonify(dict(user))


# ---------- misc ----------

@app.route("/robots.txt")
def robots():
    content = """User-agent: *
Disallow: /admin
Disallow: /admin/
Disallow: /api/v1/
Disallow: /internal/
Disallow: /checkout
Allow: /products
Allow: /
"""
    return content, 200, {"Content-Type": "text/plain"}


@app.route("/internal/config")
def internal_config():
    return jsonify({
        "app_name": "TechShop",
        "version": "2.4.1",
        "environment": "production",
        "secret_key": SECRET_KEY,
        "internal_api_key": INTERNAL_API_KEY,
        "payment_gateway_key": PAYMENT_GATEWAY_KEY,
        "db_path": DB_PATH,
        "debug": False,
        "allowed_hosts": ["techshop.vn", "www.techshop.vn", "127.0.0.1"],
        "smtp_host": "smtp.mailgun.org",
        "smtp_user": "noreply@techshop.vn",
    })


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
