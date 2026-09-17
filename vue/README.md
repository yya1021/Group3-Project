# 优选商城（电商平台）

> 前后端分离的电商交易平台：**Vue 3 前端 + Node.js/Express 后端**。
> 本项目由原「座椅联合图书馆」系统改造而来，现支持四角色权限、商城、订单、审计日志与管理员 TOTP 认证。

- 前端：Vue 3 + Vite + Vue Router
- 后端：Node.js + Express（模块化路由）
- 数据存储：`server/data/*.json`（JSON 文件，无需数据库）
- 权限模型：RBAC 四角色（管理员 / 商户 / 普通用户 / 审计员）
- 安全认证：管理员登录使用 TOTP（Microsoft Authenticator）二次认证
- 自动化测试：后端 API 测试（node:test + supertest）、前端单元测试（vitest）

## 快速开始

> 注意：本项目自带依赖已安装，可直接启动，无需 `npm install`。
> 如本地 `npm` 命令不可用（例如 PowerShell 执行策略限制或 npm 本体损坏），请使用下方「node 直启」方式。

### 方式一：node 直启（推荐，无需 npm）

开两个终端窗口：

**终端 1 —— 启动后端（端口 3000）：**

```powershell
cd vue\vue\server
node src\server.js
```

**终端 2 —— 启动前端（端口 5173）：**

```powershell
cd vue\vue
node node_modules\vite\bin\vite.js client
```

启动后访问 http://localhost:5173 即可，前端会自动把 `/api` 代理到后端 3000 端口。

### 方式二：npm 启动（npm 命令可用时）

```powershell
cd D:\code\vue\vue
npm.cmd install        # 若 PowerShell 禁止运行 npm.ps1，改用 npm.cmd
npm.cmd run dev        # 同时启动前后端
```

> PowerShell 下 `npm` 报「禁止运行脚本」时：
> - 临时放开：`Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`
> - 或直接用 `npm.cmd` 替代 `npm`

## 运行测试

```powershell
# 后端测试（node 直测，无需 npm）
cd D:\code\vue\vue\server
node --test

# 前端单元测试
cd D:\code\vue\vue
node node_modules\vitest\vitest.mjs run --root client
```

## 默认账号

| 用户名 | 密码 | 角色 | 说明 |
| ------ | ---- | ---- | ---- |
| `admin` | `admin123` | 管理员 | 首次登录需绑定 TOTP（扫码或手动输入密钥） |
| `auditor` | `auditor123` | 审计员 | 查看/导出审计日志 |

普通用户与商户可通过注册页面自助注册，注册时可选「普通用户」或「商户」。

## 角色与权限

| 角色 | 商品管理 | 订单管理 | 用户管理 | 角色管理 | 系统配置 | 审计日志 |
| ---- | -------- | -------- | -------- | -------- | -------- | -------- |
| 管理员 | 增删改查 | 增删改查 | 增删改查 | 增删改查 | 增删改查 | 无 |
| 商户 | 增删改查（仅本人店铺） | 查看 | 无 | 无 | 无 | 无 |
| 普通用户 | 查看 | 查看、新增（本人订单） | 无 | 无 | 无 | 无 |
| 审计员 | 无 | 无 | 无 | 无 | 无 | 查看、导出报告 |

- **管理员**登录需 TOTP（Microsoft Authenticator）二次认证
- **商户**登录进入商户后台，可管理本人店铺商品、查看本店订单
- **普通用户**登录进入商城，可浏览商品、下单（模拟银行认证延时 1.5~3.5 秒）
- **审计员**登录进入审计日志页，可查看并导出 CSV 报告
- 取消订单：管理员可取消任意订单，下单者本人可取消自己的订单（取消后恢复库存）

## 项目结构

```
.
├── server/                  # 后端 (Node.js + Express)
│   ├── src/
│   │   ├── server.js        # 启动入口
│   │   ├── app.js           # Express 应用（可被测试引用）
│   │   ├── config.js        # 配置
│   │   ├── middleware/      # 认证 + RBAC 权限中间件
│   │   ├── routes/          # 路由（认证/商品/订单/用户/角色/审计/文章/文件/评论）
│   │   └── services/        # 数据存储、权限矩阵、审计日志、TOTP
│   ├── data/                # JSON 数据文件（users/products/orders/audit-logs 等）
│   ├── uploads/             # 上传文件
│   └── tests/               # API 自动化测试
└── client/                  # 前端 (Vue 3 + Vite)
    ├── public/              # 静态资源
    └── src/
        ├── api/             # API 客户端 + 单元测试
        ├── stores/          # 认证状态
        ├── router/          # 路由（含角色守卫）
        ├── views/           # 页面（商城/购物车/商户后台/管理后台/审计日志等）
        └── App.vue          # 布局（导航 + 页脚）
```

## API 一览（核心接口）

| 方法 | 路径 | 说明 |
| ---- | ---- | ---- |
| POST | `/api/register` | 注册（普通用户 / 商户） |
| POST | `/api/login` | 登录（管理员进入 TOTP 流程） |
| POST | `/api/login/totp` | TOTP 二次认证 / 绑定 |
| POST | `/api/logout` | 登出 |
| GET  | `/api/me` | 当前用户信息 |
| GET  | `/api/products` | 商品列表（可选 `?type=` 分类） |
| POST | `/api/products` | 新增商品（管理员/商户） |
| PUT  | `/api/products/:id` | 修改商品（管理员/商户本人店铺） |
| DELETE | `/api/products/:id` | 删除商品（管理员/商户本人店铺） |
| GET  | `/api/cart` | 当前用户购物车 |
| POST | `/api/cart` | 更新购物车 |
| POST | `/api/orders` | 创建订单（含模拟银行认证延时） |
| GET  | `/api/orders` | 订单列表（按角色数据范围过滤） |
| DELETE | `/api/orders/:id` | 取消订单（管理员/下单者本人） |
| GET  | `/api/users` | 用户列表（管理员） |
| POST | `/api/users` | 创建用户（管理员） |
| PUT  | `/api/users/:id` | 修改用户（管理员） |
| DELETE | `/api/users/:id` | 删除用户（管理员） |
| GET  | `/api/roles` | 角色权限矩阵（管理员） |
| PUT  | `/api/roles/:role` | 更新角色权限（管理员） |
| GET  | `/api/audit-logs` | 审计日志（审计员） |
| GET  | `/api/audit-logs/export` | 导出审计报告 CSV（审计员） |