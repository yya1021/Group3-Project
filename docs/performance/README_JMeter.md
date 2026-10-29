# JMeter 压测脚本说明
- **脚本文件**：ecommerce_test.jmx
- **测试环境**：本地 Windows，后端 Node.js (端口3000)
- **运行方式**：需在 JMeter 的 bin 目录下启动，导入此 .jmx 文件运行。
- **并发配置**：500 线程，Ramp-up 10s，循环 20 次。
- **鉴权说明**：由于系统包含国密加密，本次压测采用获取真实 Token 注入 HTTP Header Manager 的方式进行。