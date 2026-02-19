# astrbot_plugin_githubapp-adopter

为 AstrBot 提供 `github_app` 平台适配能力，接收 GitHub Webhook，并支持两类自动化能力：

- 旧版 token 工具（legacy）：`github_app_issue_token`
- 新版受控写入工具（推荐）：`github_app_create_license_pr`

## 核心结论

- 旧 token 系统保留可用。
- “创建分支 + 提 PR”场景建议走新受控工具，不把 token 暴露给模型。

## 功能

- `github_app` 平台适配与会话路由
- Webhook 签名校验（`X-Hub-Signature-256`）
- Delivery 去重缓存（防重放）
- 将机器人回复回写到 GitHub Issue/PR 线程
- 自动创建并激活 GitHub skill（默认 `github_app_ops`）

## 工具说明

### `github_app_create_license_pr`（推荐）

插件内部完成：

1. 获取安装令牌（仅插件内使用）
2. 创建分支
3. 写入 `LICENSE`（MIT）
4. 创建 PR（若已存在同分支 PR，则返回已有 PR）

特点：

- 模型拿不到真实 token
- 分支/PR动作集中在单个受控入口

### `github_app_issue_token`（保留）

保留旧流程，适用于你需要自定义脚本/命令的场景。  
可通过配置 `enable_issue_token_tool` 控制启用。

## 安全与开关

- `enable_direct_repo_write_tool`: 是否启用受控写入工具（新工具开关）
- `enable_issue_token_tool`: 是否启用旧 token 工具（legacy 开关）
- `enable_privileged_write_mode`: 旧 token 流程的权限策略开关（不再影响受控 PR 工具）
- `privileged_mode_require_whitelist`: 高权限模式下是否要求 shell/python 命中白名单
- `enforce_tool_write_guard`: shell/python 风险命令防护

## 推荐配置（新旧并存）

```json
{
  "enable_direct_repo_write_tool": true,
  "enable_issue_token_tool": true,
  "enable_privileged_write_mode": false,
  "privileged_mode_require_whitelist": true,
  "enforce_tool_write_guard": true
}
```

## Webhook 地址

`http://<astrbot-host>:6185/api/platform/webhook/{webhook_uuid}`
