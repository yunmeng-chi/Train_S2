from flask import Flask, render_template, request, redirect, session, make_response, jsonify
import time
import random
import string
import uuid
import hashlib
import os
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())

USERS = {
    "admin": {
        "username": "admin",
        "password": "0192023a7bbd73250516f069df18b500",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "78d03b2810a74e5751c02db550798676",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
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
    return render_template("index.html", user=user)


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
            return render_template("index.html", user=USERS[username])
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
    return render_template("login.html", captcha_token=gen_captcha_token())


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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
