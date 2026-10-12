'use strict';

const crypto = require('crypto');

/**
 * 内置弱口令字典：仅用于**离线验证**已泄露的无盐哈希是否可被还原。
 * 之所以只需要很小的字典，是因为无盐单轮 SHA-256 没有任何计算成本抑制，
 * 攻击者用常用口令表即可覆盖大量账号。
 */
const WEAK_PASSWORD_DICT = [
  'admin123', 'admin', 'administrator', 'password', 'password123', '1234', '12345', '123456',
  '1234567', '12345678', '123456789', 'qwerty', 'abc123', '111111', '000000', 'letmein',
  'welcome', 'root', 'toor', 'test', 'test123', 'test1234', 'auditor123', 'admin@123',
  '1q2w3e4r', 'qwer1234', '1234qwer', 'passw0rd', 'iloveyou', 'monkey'
];

const WEAK_HASH_INDEX = new Map(
  WEAK_PASSWORD_DICT.map((p) => [crypto.createHash('sha256').update(p).digest('hex'), p])
);

// 尝试把 64 位十六进制摘要还原为字典中的明文口令
function crackWithDictionary(hexDigest) {
  return WEAK_HASH_INDEX.get(String(hexDigest).toLowerCase()) || null;
}

/**
 * SAST 规则库（离线可用，规则命中即产出可复核的证据行号）
 *
 * 字段说明：
 *   files        目标文件（精确路径 / 以 / 结尾的目录前缀 / 含 * 的通配）
 *   pattern      主匹配正则（用于定位并给出证据行）
 *   check        自定义检测函数，返回 [{ line, evidence, note }]
 *   aggregate    true 表示把同一规则的所有命中合并为一条发现（证据里逐条列出），
 *                用于「路由级」这类天然多点命中的规则，避免报告被同类条目淹没
 */

const RULES = [
  {
    id: 'SEC-CRED-01',
    title: '仓库中提交了凭据材料（口令哈希 / TOTP 密钥 / 恢复码哈希）',
    severity: 'CRITICAL',
    cwe: 'CWE-798',
    category: '敏感信息泄露',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/data/'],
    aggregate: true,
    description:
      'server/data 目录被纳入版本控制，其中 users.json 直接保存了管理员与测试账号的口令哈希、' +
      '管理员 TOTP 密钥（totpSecret 明文）以及一次性恢复码哈希；audit-logs.json 保存了历史操作日志。',
    impact:
      '任何能读取仓库的人（含后续被移出小组的成员、公开仓库的任何访问者）即可离线爆破口令、' +
      '并用泄露的 TOTP 密钥直接生成有效动态码，从而绕过管理员二次认证完成登录。' +
      '本扫描器已用内置弱口令字典对泄露的哈希做了离线还原验证（见下方证据），确认无需任何算力投入即可得到明文。',
    recommendation:
      '1) 立即从仓库移除 server/data/*.json 并加入 .gitignore（应用启动时会由 store.ensureStructure 自动重建）；' +
      '2) 轮换已被泄露的口令、TOTP 密钥与恢复码；' +
      '3) 历史提交中的密钥必须视为已泄露，需重写历史或直接换密钥；' +
      '4) 口令存储改为 bcrypt/Argon2 加盐哈希（见 SEC-HASH-01）。',
    check: (ctx) => {
      if (!ctx.relPath.endsWith('.json')) return [];
      const raw = ctx.content || '';
      const hits = [];
      const rx = /"(password|totpSecret|recoveryCodes)"\s*:\s*(?:"([^"]*)"|\[([^\]]*)\])/g;
      let m;
      while ((m = rx.exec(raw)) !== null) {
        const key = m[1];
        const stringValue = m[2];
        const arrayValue = m[3];
        const line = raw.slice(0, m.index).split('\n').length;

        if (arrayValue !== undefined) {
          const items = arrayValue.split(',').map((s) => s.trim()).filter(Boolean);
          if (!items.length) continue;
          if (key === 'recoveryCodes') {
            hits.push({
              line,
              evidence: ctx.linePreview(line),
              note: `恢复码哈希共 ${items.length} 条已随仓库泄露（SHA-256 无盐，16 进制 64 bit 熵不足以抵抗穷举）`
            });
          }
          continue;
        }

        if (!stringValue) continue;
        if (key === 'password') {
          const cracked = /^[0-9a-fA-F]{64}$/.test(stringValue) ? crackWithDictionary(stringValue) : null;
          hits.push({
            line,
            evidence: ctx.linePreview(line),
            note:
              `口令哈希（SHA-256 无盐）：${stringValue.slice(0, 16)}…` +
              (cracked
                ? ` → 已用内置弱口令字典**离线还原出明文：「${cracked}」**`
                : ' → 未被内置字典命中（不等于安全）')
          });
        } else if (key === 'totpSecret') {
          hits.push({
            line,
            evidence: ctx.linePreview(line),
            note: `TOTP 密钥以**明文**入库：「${stringValue}」→ 可直接生成有效动态码，二次认证失效`
          });
        }
        if (hits.length >= 8) break; // 控制噪声上限
      }
      return hits;
    }
  },

  {
    id: 'SEC-CRED-02',
    title: '源码内硬编码默认 SM2 私钥',
    severity: 'HIGH',
    cwe: 'CWE-1188',
    category: '敏感信息泄露',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/services/envelope.js'],
    pattern: /DEFAULT_PRIVATE_KEY\s*=\s*'[0-9a-fA-F]{64}'/,
    description:
      '数字信封服务的默认 SM2 私钥以字面量形式硬编码在源码中，仅在未设置环境变量 SM2_PRIVATE_KEY 时使用，' +
      '但该默认值已随仓库公开，且与前端预置公钥配对。',
    impact:
      '攻击者持有私钥即可解开任意抓包得到的数字信封，恢复被 SM4-GCM 加密的请求体明文，' +
      'Week 4 的应用层机密性保护对公开仓库部署完全失效。',
    recommendation:
      '移除内置默认私钥并在启动时强制要求 SM2_PRIVATE_KEY；缺失时直接拒绝启动。生产环境应将私钥托管于 KMS/HSM。'
  },

  {
    id: 'SEC-CRED-03',
    title: '内置默认管理员账号使用弱口令 admin123',
    severity: 'HIGH',
    cwe: 'CWE-798',
    category: '默认凭据',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/services/store.js'],
    aggregate: true,
    pattern: /hashPassword\('admin123'\)/,
    description:
      'store.ensureStructure 在数据文件缺失时自动创建口令为 admin123 的管理员账号，且 README 中公开列出该默认凭据。',
    impact:
      '未修改默认口令的部署可被直接接管；管理员又持有商品、用户、角色权限矩阵的全部权限，等同于系统完全失陷。',
    recommendation:
      '首次启动时生成随机强口令并打印/写入一次性文件，强制首登改密；禁止在文档中公布生产凭据。'
  },

  {
    id: 'SEC-HASH-01',
    title: '用户口令使用无盐单轮 SHA-256 哈希存储',
    severity: 'HIGH',
    cwe: 'CWE-916',
    category: '口令保护不当',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/services/store.js'],
    pattern: /createHash\('sha256'\)\.update\(String\(password\)\)/,
    description:
      'store.hashPassword 直接对整个口令做一次 SHA-256，未加盐、未使用慢哈希函数（bcrypt/scrypt/Argon2）。',
    impact:
      '相同口令得到相同哈希（彩虹表/批量比对），GPU 每秒可尝试数十亿次；' +
      '结合已入库的 users.json，本扫描器实测用一份 30 条的内置弱口令字典即还原出管理员与测试账号的明文口令' +
      '（还原结果见 SEC-CRED-01 的证据），说明攻击者无需任何算力投入即可得手。',
    recommendation:
      '改用 bcrypt（cost>=10）或 Argon2id，并为每条口令生成独立随机盐；历史哈希在用户下次登录时透明升级。'
  },

  {
    id: 'SEC-HASH-02',
    title: 'TOTP 恢复码使用无盐 SHA-256 哈希存储',
    severity: 'MEDIUM',
    cwe: 'CWE-916',
    category: '口令保护不当',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/services/totp.js'],
    pattern: /createHash\('sha256'\)\.update\(String\(code\)\.trim\(\)\.toUpperCase\(\)\)/,
    description: '一次性恢复码只做了大写归一化后单轮 SHA-256，恢复码本身是 16 位十六进制（64 bit），抗爆破强度不足。',
    impact: '恢复码哈希泄露后可在较短时间内被离线穷举，绕过 TOTP 二次认证直接登录管理员账号。',
    recommendation: '恢复码使用 bcrypt/Argon2 加盐哈希；同时提升恢复码熵值（建议 >=128 bit 随机）。'
  },

  {
    id: 'SEC-TOKEN-01',
    title: '会话令牌随机性依赖 Math.random()',
    severity: 'MEDIUM',
    cwe: 'CWE-338',
    category: '弱随机数',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/services/store.js'],
    pattern: /update\(username \+ Date\.now\(\) \+ Math\.random\(\)\)/,
    description: 'store.generateToken 用 username + Date.now() + Math.random() 做 SHA-256 生成登录令牌，其中只有 Math.random() 提供随机性。',
    impact:
      'Math.random() 不是密码学安全随机源，且 V8 的实现可被观测/预测；' +
      '令牌可预测意味着攻击者能伪造任一用户（含管理员）的会话，无需口令。',
    recommendation: '改用 crypto.randomBytes(32)（或 crypto.randomUUID()）生成令牌，并考虑改为服务端签名的短时效令牌。'
  },

  {
    id: 'SEC-AUTH-01',
    title: '登录逻辑保留明文口令比对分支',
    severity: 'HIGH',
    cwe: 'CWE-287',
    category: '认证缺陷',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/routes/auth.routes.js'],
    aggregate: true,
    pattern: /user\.password === password/,
    description:
      '登录时同时接受「已哈希口令」与「明文口令」两种存储格式，用于兼容历史数据并自动升级。',
    impact:
      '任何能把明文写入 users.json 的路径（例如数据文件被篡改、或旧数据迁移漏洞）都会直接形成认证绕过；' +
      '同时明文比较不具备时间恒定特性，存在时序侧信道。',
    recommendation: '移除明文比较分支；历史明文口令改由一次性迁移脚本处理，或强制重置口令。'
  },

  {
    id: 'SEC-CRYPTO-01',
    title: '数字信封未强制启用，明文请求可绕过应用层加密',
    severity: 'HIGH',
    cwe: 'CWE-693',
    category: '安全控制缺失',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/middleware/envelope.middleware.js'],
    pattern: /if \(!envelope\.isEnvelope\(req\.body\)\) return next\(\)/,
    description:
      '解密中间件对「非信封」请求体一律直接放行，即应用层加密是可选而非强制；' +
      '服务端也没有校验收到的敏感请求必须为信封格式。',
    impact:
      '攻击者（或任何脚本）只要发送明文 JSON 即可完全跳过 SM2/SM4-GCM 保护，' +
      'Week 4 的「应用层安全隧道」可被一行代码降级绕过，加密带来的机密性/完整性收益为零。',
    recommendation:
      '对敏感路由（POST/PUT/DELETE）强制要求信封格式，非信封请求直接 400 拒绝；' +
      '或在网关层统一做「信封或拒绝」的策略，并保留显式的白名单例外。'
  },

  {
    id: 'SEC-XFF-01',
    title: '无条件信任客户端伪造的代理 IP 头，审计日志可被伪造',
    severity: 'MEDIUM',
    cwe: 'CWE-348',
    category: '日志与审计缺陷',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/utils/get-client-ip.js'],
    pattern: /req\.headers\['x-forwarded-for'\]/,
    description:
      'getClientIp 依次取 cf-connecting-ip / x-forwarded-for 的请求头，未校验请求是否真的来自可信反向代理' +
      '（代码不区分直连与经代理两种情况，也不校验来源 IP 是否属于代理网段）。',
    impact:
      '攻击者可自行带上 X-Forwarded-For: 1.2.3.4 让审计日志记录任意 IP，' +
      '导致溯源、封禁与责任认定全部失效；审计报告的证明力被破坏。',
    recommendation:
      '仅在请求来源属于受信代理地址段时才采信转发头（Express 的 app.set("trust proxy", ...) 配合可信网段），' +
      '或直接记录 socket 地址并单独保存转发头用于排查。'
  },

  {
    id: 'SEC-UPLOAD-01',
    title: '文件上传未限制类型/扩展名，且上传目录被静态托管（可致存储型 XSS）',
    severity: 'HIGH',
    cwe: 'CWE-434',
    category: '不受限文件上传',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/routes/file.routes.js'],
    description:
      '上传接口只校验大小上限（50MB），对 fileType/扩展名/魔数没有任何白名单校验；' +
      '同时 app.js 将上传目录以 express.static 直接对外托管。',
    impact:
      '攻击者可上传 .html/.svg 等浏览器可执行内容，并通过 /uploads/<uuid-name> 直接访问，' +
      '形成同源下的存储型 XSS，可窃取 localStorage 中的登录令牌（见 SEC-STORAGE-01），实现会话接管。',
    recommendation:
      '建立扩展名 + MIME + 文件魔数三重白名单；上传目录禁止直接执行/渲染，' +
      '对下载响应统一设置 Content-Disposition: attachment 与 X-Content-Type-Options: nosniff；' +
      '将上传文件存放在 Web 根目录之外，通过鉴权接口按 ID 读取。',
    check: (ctx) => {
      const c = ctx.content || '';
      if (!/router\.post\('\/files'/.test(c)) return [];
      const hasWhitelist = /allowedTypes|ALLOWED_|whitelist|白名单|\.test\(fileType\)|mime/i.test(c);
      if (hasWhitelist) return [];
      const idx = c.indexOf("router.post('/files'");
      const line = c.slice(0, idx).split('\n').length;
      return [
        {
          line,
          evidence: ctx.linePreview(line),
          note: '上传处理函数内未见任何类型/扩展名白名单校验'
        }
      ];
    }
  },

  {
    id: 'SEC-UPLOAD-02',
    title: '上传文件名参与路径拼接且未做规范化校验（目录穿越写文件）',
    severity: 'HIGH',
    cwe: 'CWE-22',
    category: '路径穿越',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/routes/file.routes.js'],
    pattern: /const uniqueFileName = [^\n]*fileName;[^\n]*\n[^\n]*const filePath = path\.join\(store\.getUploadsDir\(\), uniqueFileName\)/,
    description:
      '落盘路径由用户可控的 fileName 直接拼接而成：uniqueFileName = 前缀 + fileName，' +
      '随后 path.join(uploadsDir, uniqueFileName) 未使用 path.basename 剥离目录分隔符，也未校验结果是否仍在允许目录内。',
    impact:
      'fileName 传入如 a/../../x.txt 时 path.join 会把 .. 归一化，最终文件写到上传目录之外，' +
      '可覆盖应用文件（例如覆写被 require 的业务代码）进而在服务器上执行任意代码。',
    recommendation:
      '用 path.basename(fileName) 只取基名，或改为服务端自行生成文件名（保留原名只用于展示）；' +
      '落盘前用 path.resolve 校验结果必须以 path.resolve(uploadsDir) + path.sep 开头，否则拒绝。'
  },

  {
    id: 'SEC-XSS-01',
    title: '商品名称未转义拼接进 SVG 响应（存储型 XSS）',
    severity: 'MEDIUM',
    cwe: 'CWE-79',
    category: '跨站脚本',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/routes/product.routes.js'],
    pattern: /const svg = `<svg[\s\S]{0,400}?\$\{name\}[\s\S]{0,200}?<\/svg>`/,
    description:
      '商品图片接口用模板字符串把商品名 name 直接插入 SVG 文本节点，并以 image/svg+xml 返回；' +
      'name 来自商品库、可由管理员或商户通过商品新增/修改接口写入，服务端未做任何转义。',
    impact:
      '商户可保存形如 </text><script>…</script> 的商品名，直接访问 /api/products/photo/<id> 即在同源下执行脚本，' +
      '可读取 localStorage 中的登录令牌并冒用访客/管理员身份。',
    recommendation:
      '对插入到 SVG/HTML 的数据做实体转义（& < > " ），或改为返回固定占位图并按 ID 映射颜色/文字；' +
      '同时给该响应加 Content-Security-Policy 与 X-Content-Type-Options: nosniff。'
  },

  {
    id: 'SEC-CORS-01',
    title: 'CORS 允许任意来源',
    severity: 'MEDIUM',
    cwe: 'CWE-942',
    category: '安全配置错误',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/app.js'],
    pattern: /app\.use\(cors\(\)\)/,
    description: 'Express 直接使用 cors() 默认配置，Access-Control-Allow-Origin 对任意来源回显/放通。',
    impact:
      '任意第三方站点可在受害者浏览器中直接读取本接口响应；' +
      '当前令牌走 Authorization 头而非 Cookie，风险被削弱，但一旦引入 Cookie 会话或改动鉴权方式即形成实质越权读取。',
    recommendation: '把 cors() 收敛为显式来源白名单（origin 回调或 origin 数组），并限制 allowMethods/allowHeaders。'
  },

  {
    id: 'SEC-HDR-01',
    title: '缺少安全响应头（未启用 helmet 等）',
    severity: 'MEDIUM',
    cwe: 'CWE-693',
    category: '安全配置错误',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/app.js'],
    description:
      '应用未设置 Content-Security-Policy、X-Content-Type-Options、X-Frame-Options、Referrer-Policy 等响应头，' +
      '也未使用 helmet 中间件统一加固。',
    impact:
      '缺少 nosniff 会让上传的 HTML/SVG 被浏览器按内容渲染；缺少 CSP 会放大 XSS 危害；' +
      '缺少 X-Frame-Options 使页面可被第三方站点 iframe 嵌套（点击劫持）。',
    recommendation: '引入 helmet 并至少开启 contentSecurityPolicy、noSniff、frameguard、referrerPolicy 与 HSTS（HTTPS 部署时）。详见《漏洞清单》中与之交叉验证的动态发现。',
    check: (ctx) => {
      const c = ctx.content || '';
      if (!/require\('express'\)/.test(c)) return [];
      if (/require\('helmet'\)|helmet\(/.test(c)) return [];
      const idx = c.indexOf('function createApp');
      const line = idx === -1 ? 1 : c.slice(0, idx).split('\n').length;
      return [
        {
          line,
          evidence: ctx.linePreview(line),
          note: '应用入口未引入 helmet，全局也未手动设置 nosniff / CSP / X-Frame-Options 等安全响应头'
        }
      ];
    }
  },

  {
    id: 'SEC-ERR-01',
    title: '缺少统一错误处理中间件，异常堆栈会回传客户端',
    severity: 'MEDIUM',
    cwe: 'CWE-209',
    category: '信息泄露',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/app.js'],
    description:
      'app.js 未注册四参数错误处理中间件，非生产环境下 Express 默认错误处理器会把异常堆栈与源码路径直接返回给调用方。',
    impact: '攻击者可借堆栈获取框架版本、目录结构与代码片段，为后续利用提供精准线索。',
    recommendation: '注册统一错误处理中间件，只返回错误码与人类可读提示，堆栈仅记入服务端日志；生产环境同样强制 NODE_ENV=production。',
    check: (ctx) => {
      const c = ctx.content || '';
      if (!/require\('express'\)/.test(c)) return [];
      // 四参数错误处理中间件的特征写法
      const hasErrorHandler =
        /app\.use\(\s*\(\s*err\s*,\s*req\s*,\s*res\s*,\s*next\s*\)/.test(c) ||
        /app\.use\(\s*function\s*\(\s*err\s*,/.test(c);
      if (hasErrorHandler) return [];
      const idx = c.lastIndexOf('接口不存在');
      const line = idx === -1 ? c.split('\n').length : c.slice(0, idx).split('\n').length;
      return [
        {
          line,
          evidence: ctx.linePreview(line),
          note: '在所有路由与 404 兜底之后，未注册四参数错误处理中间件'
        }
      ];
    }
  },

  {
    id: 'SEC-DOS-01',
    title: '请求体上限 50MB 且订单接口存在秒级阻塞延时',
    severity: 'MEDIUM',
    cwe: 'CWE-400',
    category: '资源耗尽',
    confidence: 'medium',
    scanner: 'sast',
    files: ['server/src/app.js'],
    pattern: /app\.use\(express\.json\(\{ limit: '50mb' \}\)\);\r?\n\s*app\.use\(express\.urlencoded\(\{ extended: true, limit: '50mb' \}\)\);/,
    description: 'JSON/urlencoded 解析上限均为 50MB，远超业务需要（上传走 Base64 复用同一通道）；上传接口亦按 50MB 计。',
    impact:
      '少量并发即可用超大请求体耗尽内存/CPU；叠加订单接口内 1.5~3.5s 的串行等待（order.routes.js），容易形成请求堆积与雪崩。',
    recommendation:
      '按路由收紧 body 上限（例如普通 JSON 256KB、上传接口单独放宽），并对上传与下单接口做并发/速率限制；' +
      '订单接口的模拟延时改为可配置并默认关闭。'
  },

  {
    id: 'SEC-RATE-01',
    title: '登录与 TOTP 校验接口无速率限制、无失败锁定',
    severity: 'HIGH',
    cwe: 'CWE-307',
    category: '认证缺陷',
    confidence: 'medium',
    scanner: 'sast',
    files: ['server/src/routes/auth.routes.js'],
    description:
      'POST /login 与 POST /login/totp 均未引入任何限流、验证码或失败计数锁定机制，代码中也不存在相关中间件。',
    impact:
      '可对账号口令做高速字典爆破；TOTP 为 6 位数字且服务端允许 ±1 个时间窗（3 个候选码），' +
      '在无限次尝试下 10^6/3 量级的猜测可在可接受时间内命中，二次认证被实质性削弱。',
    recommendation:
      '按账号 + 来源 IP 做指数退避与失败锁定（如 5 次失败锁 15 分钟），并对 /login/totp 单独限流；' +
      '接入验证码或设备指纹，同时对失败告警。',
    check: (ctx) => {
      const c = ctx.content || '';
      if (!/router\.post\('\/login'/.test(c)) return [];
      const hasRateLimit = /rateLimit|rate-limit|express-rate-limit|tooMany|429|maxAttempts|lockout/i.test(c);
      if (hasRateLimit) return [];
      const idx = c.indexOf("router.post('/login'");
      const line = c.slice(0, idx).split('\n').length;
      return [
        {
          line,
          evidence: ctx.linePreview(line),
          note: '登录路由中未见任何限流/锁定逻辑'
        }
      ];
    }
  },

  {
    id: 'SEC-CSV-01',
    title: '审计报告 CSV 导出存在公式注入（CSV Injection）',
    severity: 'MEDIUM',
    cwe: 'CWE-1236',
    category: '注入缺陷',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/src/routes/audit.routes.js'],
    description:
      '导出逻辑只对 " 和 , 与换行做转义，未处理以 = + - @ 开头、会被 Excel 当作公式求值的单元格；' +
      '而 operator/detail 等列的内容部分来自用户可控输入（用户名、商品名）。',
    impact:
      '攻击者可注册用户名为 =cmd|\' /C calc\'!A1 之类的账号或创建同名商品，' +
      '审计员下载 CSV 用 Excel 打开时触发公式执行（DDE/远程数据拉取），在审计员工位形成代码执行。',
    recommendation:
      '对每个单元格：若以 = + - @ 或制表符/回车开头，前置单引号或加前缀空格；' +
      '更稳妥的做法是导出为不带公式语义的格式（如 JSON），或在文档中明确用「文本导入」方式打开。',
    check: (ctx) => {
      const c = ctx.content || '';
      if (!/text\/csv/.test(c)) return [];
      const guardsFormula = /\^\[=\+\\-@\]|startsWith\('='\)|公式注入|formula/i.test(c);
      if (guardsFormula) return [];
      const idx = c.indexOf("res.type('text/csv");
      const line = c.slice(0, idx).split('\n').length;
      return [
        {
          line,
          evidence: ctx.linePreview(line),
          note: 'CSV 转义仅处理引号/逗号/换行，未做公式注入防护'
        }
      ];
    }
  },

  {
    id: 'SEC-STORAGE-01',
    title: '前端把登录令牌存于 localStorage',
    severity: 'LOW',
    cwe: 'CWE-922',
    category: '敏感数据存储',
    confidence: 'high',
    scanner: 'sast',
    files: ['client/src/api/'],
    pattern: /localStorage\.setItem\(TOKEN_KEY,\s*token\)/,
    description: '登录令牌以明文写入 localStorage，任意同源脚本都可读取。',
    impact:
      '一旦存在 XSS（本项目已确认 SEC-UPLOAD-01 / SEC-XSS-01 两条路径），令牌会被直接窃取，' +
      '且不随浏览器关闭失效，会话可被长期复用。',
    recommendation:
      '服务端改为 HttpOnly + Secure + SameSite 的 Cookie 承载会话；若必须用令牌，则缩短有效期并配合刷新令牌轮换。'
  },

  {
    id: 'SEC-AUTHZ-01',
    title: '接口仅校验「已登录」，缺少细粒度权限校验（越权）',
    severity: 'HIGH',
    cwe: 'CWE-862',
    category: '权限控制缺陷',
    confidence: 'high',
    scanner: 'sast',
    aggregate: true,
    description:
      '以下路由只挂了 verifyToken，没有 requirePermission：任何自行注册的普通用户（甚至商户）都能调用它们，' +
      '而这些接口在权限矩阵语义上属于管理/审核类操作。' +
      '（已按白名单排除业务上确需公开的端点，以及「仅操作本人数据」的自助端点，见文件末尾说明。）',
    impact:
      '普通用户可越权审核或删除文章与评论、删除他人上传的文件；' +
      '结合公开注册接口（POST /api/register）可零门槛获得攻击凭据，形成完整的越权链。',
    recommendation:
      '为每条路由显式声明所需资源与动作（requirePermission(\'post\',\'update\') 等），' +
      '并补充自动化测试（本项目 tests/rbac.test.js 可扩展）覆盖「低权限角色调用高权限接口应 403」。',
    check: (ctx) => routeAuthzCheck(ctx, 'MISSING_PERMISSION')
  },

  {
    id: 'SEC-AUTHZ-02',
    title: '敏感接口完全未鉴权即可访问',
    severity: 'HIGH',
    cwe: 'CWE-306',
    category: '认证缺陷',
    confidence: 'high',
    scanner: 'sast',
    aggregate: true,
    description:
      '以下路由既没有 verifyToken 也没有权限校验，匿名请求即可直接读取业务数据：' +
      '文件清单/文件详情/文件下载（这三条即为本次命中的全部端点）。' +
      '（已按白名单排除商品浏览、文章浏览、登录注册等业务上确需公开的端点，见文件末尾说明。）',
    impact:
      '匿名即可枚举并下载服务器上传目录中的全部文件（含业务附件），' +
      '文件下载接口还会把 originalName 作为下载文件名回传，构成未授权的数据外泄面。',
    recommendation:
      '按「默认拒绝」原则为文件相关路由补上鉴权，并叠加资源归属校验；' +
      '确实需要公开的接口单独列出白名单并在路由上注释说明。',
    check: (ctx) => routeAuthzCheck(ctx, 'NO_AUTH')
  },

  {
    id: 'SEC-LOG-01',
    title: '审计日志以明文 JSON 落盘且随仓库提交',
    severity: 'MEDIUM',
    cwe: 'CWE-532',
    category: '日志与审计缺陷',
    confidence: 'high',
    scanner: 'sast',
    files: ['server/data/audit-logs.json'],
    description: '审计日志写入 server/data/audit-logs.json，该文件已在版本库中（含历史操作者、时间与 IP）。',
    impact: '审计数据可被任何能读取仓库的人获取与比对，且日志文件可被直接编辑而缺乏防篡改（无哈希链/签名）。',
    recommendation: '日志目录移出版本控制并限制文件权限；引入追加写入 + 哈希链或集中式日志系统以保证审计完整性。',
    check: (ctx) => {
      const c = ctx.content || '';
      if (!/"logs"/.test(c) || !/operator/.test(c)) return [];
      const idx = c.indexOf('"logs"');
      const line = c.slice(0, idx).split('\n').length;
      const count = (c.match(/"timestamp"/g) || []).length;
      return [
        {
          line,
          evidence: ctx.linePreview(line),
          note: `审计日志文件已随仓库提交，其中包含 ${count} 条历史操作记录（operator / role / ip / timestamp 均为明文）`
        }
      ];
    }
  }
];

/**
 * 路由鉴权/授权中间件链分析。
 *
 * 说明：本项目所有路由声明均为单行形式，因此按行解析即可；
 * 多行写法会被跳过（属已知局限，基线报告中已说明）。
 *
 * 为降低误报，下列端点被显式排除——它们是「业务上确需公开」或「仅操作本人数据」的端点，
 * 缺少 requirePermission 属预期设计而非缺陷。新增此类端点时应同步补充到白名单并注释原因。
 */

// 业务上确需公开（匿名可访问）的端点
const PUBLIC_ENDPOINTS = new Set([
  'POST /login', // 登录
  'POST /login/totp', // TOTP 二次认证
  'POST /register', // 公开注册（仅允许 user / merchant）
  'GET /posts', // 已发布文章列表
  'GET /posts/:id', // 文章详情
  'POST /posts', // 投稿（进入待审核队列，属设计内的公开写入）
  'GET /products', // 商品浏览
  'GET /products/:id', // 商品详情
  'GET /products/type/:type', // 按分类浏览
  'GET /products/photo/:id', // 商品占位图
  'GET /comments/:contentType/:contentId', // 已审核评论（公开）
  'POST /comments' // 发表评论（进入待审核队列，属设计内的公开写入）
]);

// 仅操作「本人 / 自身会话」数据的端点（自助操作，或已在处理函数内做归属校验）
const SELF_SERVICE_ENDPOINTS = new Set([
  'GET /me', // 查看本人信息
  'POST /logout', // 登出
  'POST /recovery-codes/regenerate', // 处理函数内已校验 req.user.role === 'admin'
  'GET /cart', // 本人购物车
  'POST /cart', // 更新本人购物车
  'POST /files', // 任意登录用户均可上传（设计如此）
  'DELETE /orders/:id' // 处理函数内已校验 isAdmin || isOwner
]);

function routeAuthzCheck(ctx, mode) {
  const content = ctx.content || '';
  const lines = content.split(/\r?\n/);
  const hits = [];
  const routeRe = /^\s*router\.(get|post|put|patch|delete)\(\s*'([^']+)'\s*,\s*([^]*)$/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const m = routeRe.exec(line);
    if (!m) continue;
    const method = m[1].toUpperCase();
    const routePath = m[2];
    const rest = m[3];
    const hasVerify = /\bverifyToken\b/.test(rest);
    const hasPerm = /\brequirePermission\b/.test(rest);

    const signature = `${method} ${routePath}`;
    const endpointLabel = `${method} /api${routePath}`;

    if (PUBLIC_ENDPOINTS.has(signature)) continue;

    if (mode === 'NO_AUTH' && !hasVerify && !hasPerm) {
      hits.push({ line: i + 1, evidence: line.trim(), note: endpointLabel });
    }
    if (mode === 'MISSING_PERMISSION' && hasVerify && !hasPerm) {
      if (SELF_SERVICE_ENDPOINTS.has(signature)) continue;
      hits.push({ line: i + 1, evidence: line.trim(), note: endpointLabel });
    }
  }
  return hits;
}

module.exports = { RULES, routeAuthzCheck, PUBLIC_ENDPOINTS, SELF_SERVICE_ENDPOINTS };
