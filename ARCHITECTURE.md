# AegisLLM 架构与目录设计

## 核心设计理念

AegisLLM 是一个安全至上的企业级 LLM 接入网关。架构采用 **微内核 + 中间件管道（Microkernel & Middleware Pipeline）** 模式。

优先级排序：**安全 > 优雅 > 健壮 > 易用 > 轻量**

## 目录结构设计

遵循 Go 标准项目布局（Standard Go Project Layout）。

```text
AegisLLM/
├── cmd/
│   └── aegis/                # 应用程序入口
│       └── main.go
├── internal/                 # 私有应用和库代码
│   ├── config/               # 配置加载与管理
│   ├── server/               # HTTP/SSE 服务器核心
│   │   └── pipeline.go       # 中间件管道调度器
│   ├── middleware/           # 核心中间件实现
│   │   ├── auth.go           # ① Auth & JWT (虚拟密钥验证)
│   │   ├── ratelimit.go      # ② Rate Limiter (分布式令牌桶)
│   │   ├── redaction.go      # ③ PII Redaction (数据脱敏)
│   │   ├── router.go         # ④ Router & LB (智能路由)
│   │   ├── kms.go            # ⑤ KMS & Vault (密钥注入与内存覆写)
│   │   └── adapter.go        # ⑥ Protocol Adapter (协议转换)
│   ├── kms/                  # 密钥管理系统 (双层 KMS 架构)
│   │   ├── local/            # 内置 AES-256-GCM KMS
│   │   └── vault/            # HashiCorp Vault / AWS Secrets Manager 适配
│   ├── proxy/                # 代理与适配器层
│   │   ├── stream.go         # 异步非阻塞流式代理引擎 (Streaming Proxy)
│   │   └── providers/        # 各大 LLM 提供商的具体适配逻辑
│   ├── store/                # 状态与持久化存储
│   │   ├── sqlite/           # Standalone 模式存储
│   │   └── redis/            # Cluster 模式限流与黑名单
│   └── utils/                # 工具函数
│       ├── memzero.go        # 内存安全擦除工具
│       └── logger.go         # 零 PII 审计日志
├── pkg/                      # 外部可复用的库代码（如提供给其他 Go 项目使用的客户端）
├── api/                      # OpenAPI/Swagger 规范文件
├── docs/                     # 设计文档与用户手册
├── scripts/                  # 构建、部署脚本
├── Dockerfile                # 基于 Distroless 的多阶段构建镜像
├── go.mod
└── go.sum
```

## 核心模块职责说明

1.  **`internal/server/pipeline.go`**: 实现洋葱模型中间件管道，是微内核的体现。所有的请求都必须穿过管道。
2.  **`internal/middleware/kms.go` & `internal/kms/`**: 负责动态获取提供商 API Key。绝对禁止将 Key 打印到日志或长期保留在内存中。使用后调用 `utils.memzero` 清理。
3.  **`internal/proxy/stream.go`**: 流式代理引擎。在转发 SSE 数据块的同时，解析数据结构，实时计算 Token，并在流结束时写入审计日志并扣减额度。
4.  **`internal/utils/logger.go`**: 严格的审计日志记录器，仅记录元数据，屏蔽任何可能的 Prompt/Completion 文本。
