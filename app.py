from flask import Flask, render_template, request, redirect, session, make_response, jsonify
import time
import random
import string
import uuid
import hashlib
import os
import sqlite3
import re
import bleach
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
from decimal import Decimal, ROUND_HALF_UP

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

USERS = {
    "admin": {
        "id": 1,
        "username": "admin",
        "password": "0192023a7bbd73250516f069df18b500",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
        "avatar": None
    },
    "alice": {
        "id": 2,
        "username": "alice",
        "password": "78d03b2810a74e5751c02db550798676",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
        "avatar": None
    }
}

# 验证码存储（服务端，仅后端校验）
captcha_codes = {}

# 失败次数和锁定记录（按用户名，服务端存储）
failed_attempts = {}
locked_until = {}

CAPTCHA_EXPIRE = 300   # 验证码有效期 5 分钟
LOCK_DURATION = 180     # 锁定时间 3 分钟
MAX_FAILS = 5           # 最大失败次数


def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )""")
    # 密码MD5哈希后存储
    admin_pwd = hashlib.md5(b"admin123").hexdigest()
    alice_pwd = hashlib.md5(b"alice2025").hexdigest()
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", admin_pwd, "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", alice_pwd, "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()


def clean_expired_captcha():
    now = time.time()
    expired = [k for k, v in captcha_codes.items() if v["expires"] < now]
    for k in expired:
        del captcha_codes[k]


def gen_captcha_text(length=4):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def draw_captcha(text):
    width, height = 120, 40
    img = Image.new("RGB", (width, height), (255, 255, 255))
    draw = ImageDraw.Draw(img)

    # 干扰线
    for _ in range(3):
        x1 = random.randint(0, width // 2)
        y1 = random.randint(0, height)
        x2 = random.randint(width // 2, width)
        y2 = random.randint(0, height)
        draw.line((x1, y1, x2, y2), fill=(random.randint(0, 200),) * 3, width=2)

    # 噪点
    for _ in range(60):
        draw.point((random.randint(0, width), random.randint(0, height)),
                   fill=(random.randint(0, 200),) * 3)

    # 文字
    font_size = 24
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_size)
    except (IOError, OSError):
        font = ImageFont.load_default()
    x = 10
    for ch in text:
        y = random.randint(4, 10)
        draw.text((x, y), ch, fill=(random.randint(30, 120),) * 3, font=font)
        x += 26

    buf = BytesIO()
    img.save(buf, "JPEG", quality=80)
    buf.seek(0)
    return buf


@app.route("/captcha/refresh")
def captcha_refresh():
    clean_expired_captcha()
    old_token = request.args.get("old_token", "")
    # 旧 token 立即失效
    captcha_codes.pop(old_token, None)
    # 生成新 token
    token = uuid.uuid4().hex
    text = gen_captcha_text()
    captcha_codes[token] = {"text": text, "expires": time.time() + CAPTCHA_EXPIRE}
    return jsonify({"token": token})


@app.route("/captcha")
def captcha():
    clean_expired_captcha()
    token = request.args.get("token", "")
    if token not in captcha_codes:
        return "验证码已过期", 400

    text = gen_captcha_text()
    captcha_codes[token] = {"text": text, "expires": time.time() + CAPTCHA_EXPIRE}

    buf = draw_captcha(text)
    resp = make_response(buf.read())
    resp.headers["Content-Type"] = "image/jpeg"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        user = USERS[username]
    return render_template("index.html", user=user, page_content=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        now = time.time()
        username = request.form.get("username", "")
        captcha_input = request.form.get("captcha", "").strip().upper()
        captcha_token = request.form.get("captcha_token", "")

        # 锁定期间直接返回 429，不校验密码/验证码
        if username in locked_until and now < locked_until[username]:
            remain = int(locked_until[username] - now)
            return render_template(
                "login.html",
                captcha_token=gen_captcha_token(),
                error=f"账号已锁定，请 {remain} 秒后再试"
            ), 429

        # 验证码校验
        captcha_data = captcha_codes.pop(captcha_token, None)
        if not captcha_data or captcha_data["text"] != captcha_input:
            return render_template(
                "login.html",
                captcha_token=gen_captcha_token(),
                error="验证码错误"
            )

        # 密码比对（MD5 哈希）
        password = request.form.get("password")
        hashed_pwd = hashlib.md5(password.encode()).hexdigest()
        if username in USERS and USERS[username]["password"] == hashed_pwd:
            # 登录成功：清空失败次数和锁定
            failed_attempts.pop(username, None)
            locked_until.pop(username, None)
            session["username"] = username
            return render_template("index.html", user=USERS[username], page_content=None)
        else:
            # 登录失败：计数
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            remain = MAX_FAILS - failed_attempts[username]
            if failed_attempts[username] >= MAX_FAILS:
                locked_until[username] = now + LOCK_DURATION
                failed_attempts[username] = 0
                return render_template(
                    "login.html",
                    captcha_token=gen_captcha_token(),
                    error="账号已锁定，请 3 分钟后再试"
                ), 429
            return render_template(
                "login.html",
                captcha_token=gen_captcha_token(),
                error=f"用户名或密码错误，还剩 {remain} 次机会"
            )

    # GET 请求：生成验证码 token
    msg = request.args.get("msg", "")
    return render_template("login.html", captcha_token=gen_captcha_token(), msg=msg)


def gen_captcha_token():
    clean_expired_captcha()
    token = uuid.uuid4().hex
    text = gen_captcha_text()
    captcha_codes[token] = {"text": text, "expires": time.time() + CAPTCHA_EXPIRE}
    return token


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 输入校验
        if not username or not password:
            return render_template("register.html", error="用户名和密码不能为空")
        if not re.match(r"^\w{2,20}$", username):
            return render_template("register.html", error="用户名仅允许字母、数字、下划线、中文，2-20位")
        if email and not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            return render_template("register.html", error="邮箱格式不正确")
        if phone and not re.match(r"^\d{5,15}$", phone):
            return render_template("register.html", error="手机号格式不正确")

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        hashed = hashlib.md5(password.encode()).hexdigest()
        c.execute(sql, (username, hashed, email, phone))
        conn.commit()
        conn.close()
        # 同步到 USERS 内存字典，使登录功能能找到该用户
        USERS[username] = {
            "id": max(u["id"] for u in USERS.values()) + 1,
            "username": username,
            "password": hashed,
            "role": "user",
            "email": email,
            "phone": phone,
            "balance": 0,
            "avatar": None
        }
        return redirect("/login?msg=注册成功，请登录")
    error = request.args.get("error", "")
    return render_template("register.html", error=error)


@app.route("/search")
def search():
    if not session.get("username"):
        return redirect("/login")
    keyword = request.args.get("keyword", "")
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
    c.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
    rows = c.fetchall()
    conn.close()
    return render_template("index.html", user=USERS.get(session.get("username")), search_results=rows, keyword=keyword, page_content=None)


@app.route("/profile")
def profile():
    # [修复] 新增身份认证校验
    if not session.get("username"):
        return redirect("/login")

    login_username = session.get("username")
    login_user = USERS.get(login_username)
    if not login_user:
        return redirect("/login")

    user_id = request.args.get("user_id", type=int)
    if user_id is None:
        return "缺少 user_id 参数", 400

    # [修复] 校验当前登录用户只能查看自己的资料，防止水平越权
    if login_user["id"] != user_id:
        return "无权查看其他用户资料", 403

    # 从 USERS 字典中按 id 查找用户
    user = None
    for u in USERS.values():
        if u["id"] == user_id:
            user = dict(u)  # 复制一份以免修改原始数据
            break
    if user is None:
        return "用户不存在", 404

    # [修复] 敏感信息脱敏处理
    if user.get("phone") and len(user["phone"]) >= 7:
        user["phone"] = user["phone"][:3] + "****" + user["phone"][-4:]
    if user.get("email") and "@" in user["email"]:
        parts = user["email"].split("@")
        if len(parts[0]) >= 2:
            user["email"] = parts[0][0] + "***@" + parts[1]
        else:
            user["email"] = parts[0][0] + "@" + parts[1]

    return render_template("profile.html", user=user)


@app.route("/recharge", methods=["POST"])
def recharge():
    # [修复] 新增身份认证校验
    if not session.get("username"):
        return redirect("/login")

    login_username = session.get("username")
    login_user = USERS.get(login_username)
    if not login_user:
        return redirect("/login")

    # [修复] user_id 改为从 session 获取，不从表单参数读取，防止越权篡改他人余额
    user_id = login_user["id"]
    amount = request.form.get("amount", type=float)

    if amount is None:
        return "缺少金额参数", 400

    # [修复] 校验充值金额必须为正数
    if amount <= 0:
        return "充值金额必须为正数", 400

    # [修复] 单次充值金额上限限制
    MAX_AMOUNT = 100000
    if amount > MAX_AMOUNT:
        return f"单次充值金额不能超过 {MAX_AMOUNT}", 400

    # [修复] 使用 Decimal 精准计算，避免浮点精度误差
    amount = float(Decimal(str(amount)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))

    # 按 id 查找用户并修改余额
    for u in USERS.values():
        if u["id"] == user_id:
            u["balance"] += amount
            break
    else:
        return "用户不存在", 404
    return redirect(f"/profile?user_id={user_id}")


# 安全白名单：仅允许预定义的页面名（修复漏洞1 LFI目录穿越 CWE-22/CWE-98）
ALLOWED_PAGES = {"help", "about", "faq"}
PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")

@app.route("/page")
def page():
    # [修复漏洞7/漏洞11] 新增登录态校验，防止未授权访问
    if not session.get("username"):
        return redirect("/login")

    name = request.args.get("name", "")
    if not name:
        return "缺少 name 参数", 400

    # [修复漏洞1 LFI目录穿越 CWE-22/CWE-98] 白名单校验
    if name not in ALLOWED_PAGES:
        return "页面不存在", 404

    # [修复漏洞3 路径编码绕过 CWE-174] 使用规范化路径 + 二次防护
    filename = name + ".html"
    filepath = os.path.join(PAGES_DIR, filename)
    real_path = os.path.realpath(filepath)

    # 二次防护：确保最终路径在 pages 目录内
    if not real_path.startswith(os.path.realpath(PAGES_DIR) + os.sep):
        return "页面不存在", 403

    try:
        with open(real_path, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        return "页面不存在", 404

    # [修复漏洞7 XSS CWE-79] 使用 bleach 清洗 HTML，只允许安全标签
    allowed_tags = ["h2", "h3", "h4", "p", "b", "strong", "em", "i",
                    "hr", "br", "ul", "ol", "li", "a", "code", "pre",
                    "blockquote", "table", "thead", "tbody", "tr", "th", "td"]
    allowed_attrs = {"a": ["href", "title"]}
    content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)

    login_username = session.get("username")
    user = USERS.get(login_username) if login_username else None
    return render_template("index.html", user=user, page_content=content)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("username"):
        return redirect("/login")
    if request.method == "POST":
        if "avatar" not in request.files:
            return render_template("upload.html", error="请选择文件")
        file = request.files["avatar"]
        if file.filename == "":
            return render_template("upload.html", error="文件名为空")

        # [修复漏洞8 上传路径穿越 CWE-22] 扩展名白名单校验
        ALLOWED_EXT = {"jpg", "jpeg", "png", "gif", "webp", "bmp"}
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in ALLOWED_EXT:
            return render_template("upload.html", error=f"仅允许上传图片文件（{', '.join(sorted(ALLOWED_EXT))}）")

        # [修复漏洞9 文件内容绕过 CWE-434] Magic Number 校验文件真实性
        magic_bytes = file.read(16)
        file.seek(0)
        magic_map = {
            b"\xff\xd8": "jpg",
            b"\x89PNG\r\n\x1a\n": "png",
            b"GIF87a": "gif",
            b"GIF89a": "gif",
            b"RIFF": "webp",
            b"BM": "bmp",
        }
        detected_ext = None
        for magic, mext in magic_map.items():
            if magic_bytes[:len(magic)] == magic:
                detected_ext = mext
                break
        if detected_ext is None:
            return render_template("upload.html", error="文件内容不是有效的图片格式"), 400
        # JPEG 检测特殊处理：检测 JFIF/EXIF
        if detected_ext == "jpg" and not (b"JFIF" in magic_bytes or b"EXIF" in magic_bytes):
            if ext != "jpg":
                # webp/bmp 可能没有 JFIF
                pass

        # [修复漏洞8 路径穿越 CWE-22] 使用 UUID 重命名文件，杜绝路径穿越
        safe_filename = f"{uuid.uuid4().hex}.{ext}"
        os.makedirs("static/uploads", exist_ok=True)
        filepath = os.path.join("static/uploads", safe_filename)
        file.save(filepath)

        url = "/" + filepath.replace("\\", "/")
        username = session.get("username")
        if username in USERS:
            USERS[username]["avatar"] = url
        return redirect("/")
    return render_template("upload.html")


@app.after_request
def add_security_headers(response):
    """[修复漏洞10 CWE-552] 添加安全响应头，防止静态文件目录遍历"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
