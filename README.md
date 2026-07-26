# 用户管理系统 (User Management System)

基于 Flask 构建的 Web 用户管理系统，具备完整的用户注册、登录认证、个人中心、充值、密码修改、搜索、头像上传、动态页面、Ping 诊断等功能模块。

## 项目结构

```
├── app.py                 # 主应用入口（Flask 路由 + 业务逻辑）
├── pages/                 # 动态页面静态文件
│   └── help.html          # 帮助中心页面
├── static/
│   ├── css/
│   │   └── style.css      # 全局样式表
│   └── uploads/           # 用户头像上传目录
├── templates/             # Jinja2 模板文件
│   ├── base.html          # 基础模板（导航栏 + 布局）
│   ├── index.html         # 首页（用户信息 + 搜索）
│   ├── login.html         # 登录页
│   ├── register.html      # 注册页
│   ├── profile.html       # 个人中心（信息展示 + 充值 + 改密）
│   ├── upload.html        # 头像上传页
│   └── ping.html          # Ping 网络诊断页
└── data/                  # SQLite 数据库目录
    └── users.db           # 用户数据
```

## 功能模块

| 功能 | 路由 | 说明 |
|------|------|------|
| 首页 | `GET /` | 登录后显示用户信息与搜索入口 |
| 登录 | `GET/POST /login` | 支持验证码 + 失败锁定机制 |
| 注册 | `GET/POST /register` | 用户名/密码/邮箱/手机注册 |
| 退出 | `POST /logout` | 清除 Session（CSRF 保护） |
| 个人中心 | `GET /profile` | 查看本人资料（手机/邮箱脱敏） |
| 充值 | `POST /recharge` | 正数金额充值（上限 100000） |
| 修改密码 | `POST /change-password` | 需原密码验证 |
| 用户搜索 | `GET /search` | 按用户名/邮箱模糊搜索 |
| 头像上传 | `GET/POST /upload` | 支持 JPG/PNG/GIF/WebP/BMP |
| 帮助中心 | `GET /page?name=help` | 动态页面加载 |
| 欢迎页 | `GET /welcome` | 个性化欢迎页面 |
| 意见反馈 | `GET/POST /feedback` | 用户留言反馈 |
| Ping 诊断 | `GET/POST /ping` | 网络连通性测试 |

## 快速启动

```bash
pip install flask pillow bleach
cd /opt/Class01
python3 app.py
```

访问 `http://localhost:5000`

### 预置账号

| 用户名 | 密码 | 角色 | 余额 |
|--------|------|------|------|
| admin | admin123 | 管理员 | ¥99,999 |
| alice | alice2025 | 普通用户 | ¥100 |

## 安全漏洞修复汇总

本项目在开发过程中进行了多轮安全审计与修复，以下是全部已修复漏洞清单：

### CSRF 跨站请求伪造
- ✅ 全站 POST 接口增加 CSRF Token 机制（绑定 Session + 一次性 + 过期）
- ✅ SameSite Cookie 配置（`Lax` 模式）
- ✅ `/logout` 改为仅接受 POST 方法
- ✅ Token 非空强制校验（防止删除绕过）
- ✅ Token 与 Session 唯一绑定（防止固定复用）

### XSS 跨站脚本攻击
- ✅ 反射型 XSS：`sanitize_output()` 消毒函数过滤 `msg`/`error`/`keyword`
- ✅ 存储型 XSS：Jinja2 auto-escape + 服务端双层过滤
- ✅ DOM XSS：移除 `onclick` + `location.href` 拼接操作
- ✅ CSP 内容安全策略头

### SSTI 服务端模板注入
- ✅ `/welcome` 和 `/feedback` 路由修复：f-string → 模板变量传参
- ✅ 用户输入通过 `render_template_string(..., name=name)` 关键字传参
- ✅ 禁止在模板字符串中使用 Python f-string 拼接

### 命令注入 (OS Command Injection)
- ✅ `/ping` 路由修复：`ipaddress.IPv4Address()` IP 白名单校验
- ✅ 参数列表替代 f-string 拼接：`["ping", "-c", "3", ip]`
- ✅ `shell=False` 禁用 Shell 解析

### 文件包含与上传
- ✅ `/page` 路由白名单机制 + `os.path.realpath()` 二次路径防护
- ✅ 上传文件 UUID 重命名（防止路径穿越）
- ✅ Magic Number 文件内容真实性校验
- ✅ 文件扩展名白名单 + 安全响应头

### 越权与逻辑漏洞
- ✅ `/profile` 接口增加 user_id 归属校验
- ✅ `/recharge` 仅从 session 获取 user_id
- ✅ 修改密码增加原密码校验 + session 用户绑定
- ✅ 手机号/邮箱脱敏显示
- ✅ 充值金额正数 + 上限校验 + Decimal 精度计算
