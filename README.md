# astrbot_plugin_githubapp-adopter

一个用于 AstrBot 的 GitHub App 平台适配插件。

本插件会注册 `github_app` 平台适配器，接收 GitHub App Webhook 事件并注入 AstrBot 事件总线。  
支持事件订阅筛选、`.pem` 私钥上传、签名校验、事件去重与动态 Session 路由。

## 功能特性

- 注册平台适配器：`github_app`
- Webhook 接入：统一 Webhook 模式（`/api/platform/webhook/{webhook_uuid}`）
- 事件筛选：可按事件类型配置接收范围
- 私钥上传：支持在插件配置中上传 `.pem` 文件
- 安全增强：
  - `X-Hub-Signature-256` HMAC 校验
  - Delivery 去重（防重放）
- 会话路由（动态 Session）：
  - Issue / PR 事件 -> 绑定到具体线程
  - Push / Star / Release 等全局事件 -> 绑定到仓库全局会话

## 会话路由策略

### 线程型事件

- `issues` / `issue_comment`  
  `github:{owner}/{repo}:issue:{issue_number}`
- `pull_request` / `pull_request_review` / `pull_request_review_comment`  
  `github:{owner}/{repo}:pr:{pull_number}`
- `discussion` / `discussion_comment`  
  `github:{owner}/{repo}:discussion:{discussion_number}`

### 全局事件

- `push` / `watch` / `fork` / `release` 等  
  `github:{owner}/{repo}:global`

## 配置说明

### 1) 插件配置（用于上传私钥与全局默认值）

在插件配置页设置：

- `private_key_files`：上传 `.pem` 私钥文件（支持多文件，实际取第一个可用文件）
- `default_github_events`：默认事件订阅列表（空=全部支持事件）
- `default_wake_event_types`：默认唤醒 LLM 的事件类型
- `enable_signature_validation`：是否启用签名校验
- `delivery_cache_ttl_seconds`：去重缓存 TTL
- `delivery_cache_max_entries`：去重缓存最大容量

### 2) 平台配置（新增一个 `github_app` 平台）

在 AstrBot 平台配置中新增并启用一条：

- `type`: `github_app`
- `id`: 自定义（建议 `github_app`）
- `github_app_id`: GitHub App ID
- `github_webhook_secret`: GitHub Webhook Secret
- `github_events`: 事件订阅列表（空=继承插件默认，若插件默认也空则为全部支持事件）
- `wake_event_types`: 触发 LLM 唤醒的事件列表
- `unified_webhook_mode`: `true`

## Webhook 地址

本插件使用 AstrBot 统一 Webhook 路由：

`http://<astrbot-host>:6185/api/platform/webhook/{webhook_uuid}`

其中 `{webhook_uuid}` 由平台配置自动生成。

> 如果你需要对外固定为 `/github`，请在反向代理层将 `/github` 转发到上面的统一 Webhook 地址。

## 已支持事件

- issues
- issue_comment
- pull_request
- pull_request_review
- pull_request_review_comment
- push
- release
- discussion
- discussion_comment
- watch
- fork

## 说明

- 当前版本默认只处理“接收与路由”链路；`send_by_session` 不会主动回写 GitHub。
- 日志中不会输出私钥、secret、签名原文。
