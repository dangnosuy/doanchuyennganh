import sqlite3
import hashlib
import os
from datetime import datetime, timedelta
import json

DB_PATH = os.environ.get("DB_PATH", "/data/techshop.db")


def md5(s):
    return hashlib.md5(s.encode()).hexdigest()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            balance REAL NOT NULL DEFAULT 0.0,
            points INTEGER NOT NULL DEFAULT 0,
            full_name TEXT,
            phone TEXT,
            address TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT NOT NULL,
            stock INTEGER NOT NULL DEFAULT 100,
            image_url TEXT,
            featured INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            total REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            address TEXT,
            items TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS coupon_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            coupon_code TEXT NOT NULL,
            used_at TEXT NOT NULL
        );
    """)

    # Users
    users = [
        (1, "admin", "admin@techshop.vn", md5("Admin@123"), "admin", 9999.0, 5000,
         "Administrator", "0901000001", "123 Admin St, HCM", "2024-01-01 00:00:00"),
        (2, "alice", "alice@example.com", md5("Alice@123"), "user", 500.0, 1200,
         "Alice Nguyen", "0901000002", "456 Le Loi, HCM", "2024-01-15 08:00:00"),
        (3, "bob", "bob@example.com", md5("Bob@123"), "user", 200.0, 300,
         "Bob Tran", "0901000003", "789 Nguyen Hue, HCM", "2024-02-01 10:00:00"),
        (4, "charlie", "charlie@example.com", md5("Charlie@123"), "user", 50.0, 100,
         "Charlie Le", "0901000004", "321 Hai Ba Trung, HN", "2024-03-01 12:00:00"),
    ]

    for u in users:
        c.execute("""INSERT OR IGNORE INTO users
            (id, username, email, password, role, balance, points, full_name, phone, address, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""", u)

    # Products
    products = [
        ("MacBook Pro 14\" M3", "Laptop Apple mạnh mẽ với chip M3, màn hình Liquid Retina XDR 14 inch, pin 18 giờ.", 52990000, "laptop", 15, "https://placehold.co/300x200?text=MacBook+Pro", 1),
        ("Dell XPS 15", "Laptop cao cấp Dell với màn hình OLED 15.6 inch, Intel Core i7 thế hệ 13, RAM 32GB.", 39990000, "laptop", 20, "https://placehold.co/300x200?text=Dell+XPS+15", 1),
        ("Lenovo ThinkPad X1 Carbon", "Laptop doanh nhân siêu mỏng nhẹ, bảo mật tốt, pin 15 giờ, chuẩn MIL-SPEC.", 32990000, "laptop", 12, "https://placehold.co/300x200?text=ThinkPad+X1", 0),
        ("ASUS ROG Strix G16", "Laptop gaming mạnh mẽ, RTX 4070, màn hình 165Hz, tản nhiệt vượt trội.", 34990000, "laptop", 8, "https://placehold.co/300x200?text=ASUS+ROG", 0),
        ("iPhone 15 Pro Max", "Smartphone Apple cao cấp, chip A17 Pro, camera 48MP ProRAW, titanium design.", 34990000, "phone", 30, "https://placehold.co/300x200?text=iPhone+15+Pro", 1),
        ("Samsung Galaxy S24 Ultra", "Smartphone Android hàng đầu, S Pen tích hợp, camera 200MP, AI features.", 29990000, "phone", 25, "https://placehold.co/300x200?text=Galaxy+S24", 1),
        ("Google Pixel 8 Pro", "Smartphone Google, Tensor G3, camera AI tốt nhất, Android thuần, 7 năm update.", 22990000, "phone", 18, "https://placehold.co/300x200?text=Pixel+8+Pro", 0),
        ("Xiaomi 14 Ultra", "Flagship Xiaomi, Snapdragon 8 Gen 3, camera Leica, sạc 90W siêu nhanh.", 19990000, "phone", 22, "https://placehold.co/300x200?text=Xiaomi+14+Ultra", 0),
        ("iPad Pro 12.9\" M2", "Tablet Apple mạnh nhất, chip M2, màn hình Liquid Retina XDR, hỗ trợ Apple Pencil 2.", 27990000, "tablet", 20, "https://placehold.co/300x200?text=iPad+Pro", 1),
        ("Samsung Galaxy Tab S9 Ultra", "Tablet Android cao cấp, màn hình AMOLED 14.6 inch, S Pen included.", 23990000, "tablet", 15, "https://placehold.co/300x200?text=Galaxy+Tab+S9", 0),
        ("AirPods Pro 2nd Gen", "Tai nghe không dây Apple, ANC chủ động, âm thanh Spatial Audio, chip H2.", 6490000, "accessories", 50, "https://placehold.co/300x200?text=AirPods+Pro", 1),
        ("Apple Watch Series 9", "Đồng hồ thông minh Apple, màn hình Always-On, theo dõi sức khỏe toàn diện.", 10990000, "accessories", 35, "https://placehold.co/300x200?text=Apple+Watch", 0),
        ("Anker 65W GaN Charger", "Sạc đa năng 65W GaN nhỏ gọn, 3 cổng USB-C + USB-A, tương thích rộng.", 890000, "accessories", 100, "https://placehold.co/300x200?text=Anker+Charger", 0),
        ("Logitech MX Master 3S", "Chuột không dây cao cấp, cảm biến 8000 DPI, kết nối đa thiết bị, êm ái.", 2290000, "accessories", 60, "https://placehold.co/300x200?text=MX+Master+3S", 0),
    ]

    for p in products:
        c.execute("""INSERT OR IGNORE INTO products
            (name, description, price, category, stock, image_url, featured)
            VALUES (?,?,?,?,?,?,?)""", p)

    conn.commit()

    # Get product IDs for seeding orders
    prods = {row["name"]: row["id"] for row in c.execute("SELECT id, name FROM products").fetchall()}
    alice_id = 2
    bob_id = 3

    # Alice orders
    orders = [
        (alice_id, 52990000 + 34990000, "delivered", "456 Le Loi, HCM",
         json.dumps([{"product_id": 1, "name": "MacBook Pro 14\" M3", "price": 52990000, "qty": 1},
                     {"product_id": 5, "name": "iPhone 15 Pro Max", "price": 34990000, "qty": 1}]),
         "2024-03-10 14:00:00"),
        (alice_id, 6490000, "shipped", "456 Le Loi, HCM",
         json.dumps([{"product_id": 11, "name": "AirPods Pro 2nd Gen", "price": 6490000, "qty": 1}]),
         "2024-04-01 09:30:00"),
        (alice_id, 2290000 * 2, "pending", "456 Le Loi, HCM",
         json.dumps([{"product_id": 14, "name": "Logitech MX Master 3S", "price": 2290000, "qty": 2}]),
         "2024-04-10 16:00:00"),
        (bob_id, 29990000, "delivered", "789 Nguyen Hue, HCM",
         json.dumps([{"product_id": 6, "name": "Samsung Galaxy S24 Ultra", "price": 29990000, "qty": 1}]),
         "2024-03-20 11:00:00"),
    ]

    for o in orders:
        existing = c.execute("SELECT id FROM orders WHERE user_id=? AND created_at=?", (o[0], o[5])).fetchone()
        if not existing:
            c.execute("""INSERT INTO orders (user_id, total, status, address, items, created_at)
                VALUES (?,?,?,?,?,?)""", o)

    conn.commit()
    conn.close()
    print("Database initialized successfully.")


if __name__ == "__main__":
    init_db()
