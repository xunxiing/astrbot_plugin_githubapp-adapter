# astrbot_plugin_githubapp-adopter

一个用于 AstrBot 的 GitHub App Webhook 平台适配插件。

本插件会注册 `github_app` 平台适配器，用于接收 GitHub App 的 Webhook 事件并注入 AstrBot 事件总线。

## 功能

- 平台适配器：`github_app`
- Webhook 接入：使用 AstrBot 统一 Webhook 模式（`/api/platform/webhook/{webhook_uuid}`）
- 事件订阅：按事件类型筛选接收范围（allowlist）
- 私钥配置：插件配置页支持上传 `.pem` 私钥文件
- 安全增强：
  - `X-Hub-Signature-256` HMAC 校验（可开关）
  - Delivery 去重（防重放）
- 动态 Session 路由（符合 GitHub 线性 Thread 交互）：
  - Issue / PR / Discussion -> 绑定到具体编号线程
  - Push / Star / Release 等全局事件 -> 绑定到仓库全局会话

## Session 路由策略

- `issues` / `issue_comment`  
  `github:{owner}/{repo}:issue:{issue_number}`
- `pull_request` / `pull_request_review` / `pull_request_review_comment`  
  `github:{owner}/{repo}:pr:{pull_number}`
- `discussion` / `discussion_comment`  
  `github:{owner}/{repo}:discussion:{discussion_number}`
- 其他事件（如 `push` / `watch` / `fork` / `release`）  
  `github:{owner}/{repo}:global`

## 配置说明

### 1) 插件配置（私钥在这里上传）

在插件配置页设置：

- `private_key_files`：上传 `.pem` 私钥文件（支持多个，实际取第一个可用文件）
- `default_github_events`：默认订阅事件列表（空 = 全部支持事件）
- `default_wake_event_types`：默认唤醒 LLM 的事件类型列表
- `enable_signature_validation`：是否启用签名校验
- `delivery_cache_ttl_seconds`：去重 TTL
- `delivery_cache_max_entries`：去重缓存上限

### 2) 平台配置（新增一个 `github_app` 平台）

在 AstrBot 平台配置中新增并启用一条：

- `type`: `github_app`
- `id`: 自定义（建议 `github_app`）
- `github_app_id`: GitHub App ID
- `github_webhook_secret`: GitHub Webhook Secret
- `github_events`: 订阅事件列表（空 = 继承插件默认；若插件默认也为空则为全部支持事件）
- `wake_event_types`: 唤醒 LLM 的事件列表
- `unified_webhook_mode`: `true`

## Webhook 地址

本插件使用 AstrBot 统一 Webhook 路由：

`http://<astrbot-host>:6185/api/platform/webhook/{webhook_uuid}`

其中 `{webhook_uuid}` 会在创建平台配置时自动生成。

如果你需要对外固定为 `/github`，建议在反向代理层将 `/github` 转发到上面的统一 Webhook 地址。

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

- `send_by_session` 支持向 Issue / PR 线程回写评论（通过 GitHub App Installation Token 调用 API）。
- 日志不会输出私钥、secret 或签名原文。
