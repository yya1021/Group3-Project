# 优选商城（电商平台）

> 前后端分离的电商交易平台：**Vue 3 前端 + Node.js/Express 后端**。
> 本项目由原「座椅联合图书馆」系统改造而来，现支持四角色权限、商城、订单、审计日志与管理员 TOTP 认证。

- 前端：Vue 3 + Vite + Vue Router
- 后端：Node.js + Express（模块化路由）
- 数据存储：`server/data/*.json`（JSON 文件，无需数据库）
- 权限模型：RBAC 四角色（管理员 / 商户 / 普通用户 / 审计员）
- 安全认证：管理员登录使用 TOTP（Microsoft Authenticator）二次认证
- 传输加密：敏感请求 Body 使用「数字信封」（SM2 封装会话密钥 + SM4-GCM 加密）+ 时间窗/重放校验
- 自动化测试：后端 API 测试（node:test + supertest）、前端单元测试（vitest）

## 快速开始

> 注意：`node_modules/` 与构建产物已加入 `.gitignore` 不入库；首次克隆后请先在仓库根目录执行 `npm install` 安装依赖。


开两个终端窗口：

**终端 1 —— 启动后端（端口 3000）：**


cd vue\server
node src\server.js

**终端 2 —— 启动前端（端口 5173）：**

cd vue
node node_modules\vite\bin\vite.js client

启动后访问 http://localhost:5173 即可，前端会自动把 `/api` 代理到后端 3000 端口。

## 运行测试

```powershell
# 后端测试（node 直测，无需 npm）
cd D:\code\vue\server
node --test

# 前端单元测试
cd D:\code\vue
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

## 传输加密（数字信封）

在不改造底层 TLS 的前提下，对携带 JSON Body 的敏感请求（POST/PUT/DELETE）统一做应用层加密：

1. 客户端每次请求生成随机 **SM4 会话密钥（128 bit）** 与 **Nonce（96 bit）**；
2. 用 **SM4-GCM** 对 Body 做认证加密（同时提供机密性、完整性与抗篡改）；
3. 用服务端 **SM2 公钥** 封装会话密钥，形成**数字信封**；
4. 服务端完成「SM2 解封 → 时间窗校验 → 重放校验 → SM4-GCM 解密」。

信封结构（JSON）：

| 字段 | 含义 |
| --- | --- |
| `enc` | 固定为 `sm2-sm4-gcm` |
| `v` | 协议版本 |
| `ts` | 客户端时间戳（用于时间窗校验） |
| `nonce` | Base64 的 96 bit 随机数（GCM IV，同时用于重放去重） |
| `ek` | SM2 加密后的会话密钥（数字信封，C1C3C2 hex） |
| `ct` | Base64 密文 |
| `tag` | Base64 的 GCM 认证标签 |

抓包可见的 Body 仅为上述信封字段，敏感明文不会出现。

> ⚠️ **本机制不能替代生产环境 HTTPS。** 应用层加密仅保护 Body 的机密性与完整性，不提供服务器身份认证、前向保密与密钥的安全分发。生产环境必须叠加 HTTPS；SM2 私钥应通过环境变量 `SM2_PRIVATE_KEY` 注入或托管于 KMS/HSM，公钥经 HTTPS 下发或预置并定期轮换。

关键实现：

- 后端：`server/src/services/sm4-gcm.js`（SM4-GCM）、`server/src/services/envelope.js`（数字信封解封）、`server/src/services/replay.js`（时间窗 + 重放）、`server/src/middleware/envelope.middleware.js`（解密中间件，挂载于 `app.js`）。
- 前端：`client/src/api/sm4gcm.js`、`client/src/api/envelope.js`，并在 `client/src/api/index.js` 的 `fetch` 封装层统一加密封装。

> 国密算法依赖 `sm-crypto`（含其传递依赖 `jsbn`）。本项目已自带该依赖，直接使用即可。

## 项目结构

```
.
├── server/                  # 后端 (Node.js + Express)
│   ├── src/
│   │   ├── server.js        # 启动入口
│   │   ├── app.js           # Express 应用（可被测试引用）
│   │   ├── config.js        # 配置
│   │   ├── middleware/      # 认证 + RBAC 权限 + 数字信封解密中间件
│   │   ├── routes/          # 路由（认证/商品/订单/用户/角色/审计/文章/文件/评论）
│   │   └── services/        # 数据存储、权限矩阵、审计日志、TOTP、数字信封、重放防护、SM4-GCM
│   ├── data/                # JSON 数据文件（users/products/orders/audit-logs 等）
│   ├── uploads/             # 上传文件
│   └── tests/               # API 自动化测试
└── client/                  # 前端 (Vue 3 + Vite)
    ├── public/              # 静态资源
    └── src/
        ├── api/             # API 客户端（fetch 封装 + 数字信封加密）+ 单元测试
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