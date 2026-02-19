# astrbot_plugin_githubapp-adopter

一个为 AstrBot 提供 `github_app` 平台适配能力的插件，用于接入 GitHub App Webhook 事件。

插件可将 GitHub 事件映射为 AstrBot 会话，并支持将机器人回复回写到 Issue/PR 线程（基于 GitHub App Installation Token）。

## 功能概览

- `github_app` 平台适配器
- 统一 webhook 路由（`/api/platform/webhook/{webhook_uuid}`）
- 事件类型白名单过滤
- webhook 签名校验（`X-Hub-Signature-256`）
- Delivery 去重缓存（防重放）
- 按仓库/线程动态会话路由
- 回写评论到 GitHub Issue/PR
- 插件加载后自动创建并激活 GitHub skill
- 提供临时令牌工具：`github_app_issue_token`

## 已支持事件

- `issues`
- `issue_comment`
- `pull_request`
- `pull_request_review`
- `pull_request_review_comment`
- `push`
- `release`
- `discussion`
- `discussion_comment`
- `watch`
- `fork`

## 会话路由

- `issues` / `issue_comment` -> `github:{owner}/{repo}:issue:{issue_number}`
- `pull_request` / `pull_request_review` / `pull_request_review_comment` -> `github:{owner}/{repo}:pr:{pull_number}`
- `discussion` / `discussion_comment` -> `github:{owner}/{repo}:discussion:{discussion_number}`
- 其他事件 -> `github:{owner}/{repo}:global`

## 配置说明

### 插件配置（`_conf_schema.json`）

- `private_key_files`：上传 GitHub App `.pem` 私钥
- `default_github_events`：默认事件订阅列表
- `default_wake_event_types`：默认事件唤醒列表
- `enable_signature_validation`：是否开启 webhook 签名校验
- `delivery_cache_ttl_seconds`：去重缓存 TTL
- `delivery_cache_max_entries`：去重缓存上限
- `auto_create_github_skill`：插件加载时自动创建/更新 skill
- `github_skill_name`：`data/skills` 下 skill 目录名
- `overwrite_github_skill`：是否覆盖插件生成的 `SKILL.md`

### 平台配置（新增 `github_app` 平台）

- `type`: `github_app`
- `id`: 自定义平台 ID（例如 `github_app`）
- `github_app_id`: GitHub App ID
- `github_webhook_secret`: webhook 密钥
- `github_api_base_url`: 默认 `https://api.github.com`
- `github_events`: 订阅事件（空则使用插件默认）
- `wake_event_types`: 按事件类型触发唤醒
- `wake_on_mentions`: 被 @ 时唤醒
- `mention_target_logins`: 提及目标登录名白名单
- `ignore_bot_sender_events`: 忽略 bot 发送者事件
- `github_signature_validation`: 签名校验开关
- `github_delivery_cache_ttl_seconds`: 去重 TTL 覆盖值
- `github_delivery_cache_max_entries`: 去重上限覆盖值
- `unified_webhook_mode`: `true`
- `webhook_uuid`: 在平台面板中自动生成

## 临时令牌工作流

1. Agent 调用 `github_app_issue_token`
2. 插件返回短期 Installation Token
3. Agent 将令牌写入环境变量（`GH_TOKEN`）并执行 `gh` / `git` / `curl`
4. 任务完成后立即清理 `GH_TOKEN`

该方式避免向模型暴露永久凭据。

## Webhook 地址

`http://<astrbot-host>:6185/api/platform/webhook/{webhook_uuid}`

如果你希望对外固定为 `/github`，可在反向代理层将该路径转发到上面的统一 webhook 地址。