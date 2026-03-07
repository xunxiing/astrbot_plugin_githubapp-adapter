# astrbot_plugin_githubapp-adapter

用于 AstrBot 的 GitHub App 适配插件，提供 GitHub App Webhook 回调适配与受控仓库操作能力。

## 功能特性

### 核心功能
- **GitHub App Webhook 适配**：接收并处理 GitHub 各类事件回调
- **安全仓库操作**：提供只读仓库操作工具，包括：
  - 目录浏览：按层级查看仓库文件结构
  - 文件读取：分段读取大文件内容
  - 代码搜索：在仓库内搜索代码片段
- **安全模型**：
  - 假令牌桥接：向模型提供短期假令牌，执行前替换为真实只读令牌
  - 沙盒工作区：自动准备隔离的工作环境
  - 令牌防护：可选拦截明文令牌字面量
- **智能会话管理**：自动识别仓库、线程类型和编号
- **图片处理**：自动下载并处理 GitHub 事件中的图片附件

### 支持的事件类型
- Issues（问题）
- Issue Comment（问题评论）
- Pull Request（拉取请求）
- Pull Request Review（PR 审查）
- Pull Request Review Comment（PR 审查评论）
- Push（推送）
- Release（发布）
- Discussion（讨论）
- Discussion Comment（讨论评论）
- Watch（关注）
- Fork（分叉）

## 部署完整流程

### 前置要求

1. **AstrBot 环境**
   - 已安装并运行 AstrBot v0.2.0 或更高版本
   - 具备管理员权限
   - 服务器有公网 IP 或域名（用于接收 GitHub Webhook）

2. **系统依赖**
   - Python 3.9+
   - OpenSSL（用于 JWT 签名）
   - Git（用于沙盒工作区克隆）

3. **网络要求**
   - 能够访问 GitHub API (`api.github.com`)
   - 能够接收来自 GitHub 的 Webhook 请求
   - 服务器端口 6185 可访问（或配置反向代理）

### 步骤 1：创建 GitHub App

#### 1.1 访问 GitHub App 设置页面
1. 登录 GitHub 账号
2. 进入 **Settings** → **Developer settings** → **GitHub Apps**
3. 点击 **New GitHub App**

#### 1.2 填写应用基本信息
- **GitHub App name**：输入应用名称（如 `astrbot-github-app`）
- **Homepage URL**：填写 AstrBot 服务器地址
- **Webhook URL**：`http://<你的服务器IP>:6185/api/platform/webhook/{webhook_uuid}`（本部分的url可以先随便填一个，后面配置好了再改为正确的）
  - 在后续配置插件后，从 AstrBot 管理界面获取具体的 `webhook_uuid`
- **Webhook secret**：生成一个强随机字符串，后续配置需要使用

#### 1.3 配置权限
在 **Repository permissions** 中设置以下权限：

| 权限 | 级别 | 说明 |
|------|------|------|
| **Contents** | Read-only | 读取仓库内容 |
| **Issues** | Read & write | 读取和创建 Issue 评论 |
| **Pull requests** | Read & write | 读取和创建 PR 评论 |
| **Discussions** | Read & write | 读取和创建 Discussion 评论 |
| **Metadata** | Read-only | 读取仓库元数据 |

#### 1.4 订阅事件
在 **Subscribe to events** 中勾选需要的事件：
- [x] Issues
- [x] Issue comment
- [x] Pull request
- [x] Pull request review
- [x] Pull request review comment
- [x] Push
- [x] Release
- [x] Discussion
- [x] Discussion comment
- [x] Watch
- [x] Fork

#### 1.5 生成私钥
1. 点击 **Generate a private key**
2. 保存生成的 `.pem` 文件（如 `astrbot-github-app.2025-03-07.private-key.pem`）
3. 记录 **App ID**（显示在应用设置页面顶部）

#### 1.6 安装应用
1. 在应用设置页面，点击 **Install App**
2. 选择要安装的仓库或组织
3. 确认安装

### 步骤 2：安装插件

#### 2.1 通过 AstrBot 管理界面安装
1. 访问 AstrBot 管理界面
2. 进入 **插件管理** → **插件商店**
3. 搜索 `githubapp-adapter`
4. 点击安装

#### 2.2 手动安装（开发模式）
```bash
# 进入 AstrBot 插件目录
cd AstrBot/data/plugins

# 克隆插件仓库
git clone https://github.com/example/astrbot_plugin_githubapp-adapter.git

# 安装依赖
pip install -r astrbot_plugin_githubapp-adapter/requirements.txt
```

### 步骤 3：配置插件

#### 3.1 基础配置
在 AstrBot 管理界面中配置以下参数：

**平台配置（在平台设置中）**
- `github_app_id`：GitHub App 的 App ID
- `github_webhook_secret`：Webhook secret（与 GitHub App 设置一致）
- `github_api_base_url`：默认 `https://api.github.com`（企业版可修改）
- `github_events`：订阅的事件列表（留空表示全部）
- `wake_event_types`：触发唤醒的事件类型（默认：`issues`, `pull_request`）
- `wake_on_mentions`：是否在 @提及时唤醒（默认：`true`）
- `mention_target_logins`：提及目标登录名列表（如 `["my-bot"]`）
- `ignore_bot_sender_events`：忽略机器人发送者事件（默认：`true`）
- `github_signature_validation`：启用签名校验（默认：`true`）
- `github_delivery_cache_ttl_seconds`：投递去重缓存时长（默认：`900`）
- `github_delivery_cache_max_entries`：投递去重缓存最大条目数（默认：`10000`）

**插件配置（在插件设置中）**
- `private_key_files`：上传私钥文件（`.pem`）
- `default_github_events`：默认订阅事件
- `default_wake_event_types`：默认唤醒事件类型 **（建议勾选几个）**
- `default_wake_on_mentions`：默认提及唤醒
- `default_mention_target_logins`：默认提及目标
- `default_ignore_bot_sender_events`：默认忽略机器人事件
- `enable_signature_validation`：启用签名校验
- `delivery_cache_ttl_seconds`：投递缓存时长
- `delivery_cache_max_entries`：投递缓存最大条目
- `auto_create_github_skill`：自动创建平台技能（默认：`true`）
- `github_skill_name`：平台技能名称（默认：`github_app_ops`）
- `overwrite_github_skill`：覆盖已生成技能（默认：`true`）
- `enable_fake_token_bridge`：启用假令牌桥接（默认：`true`）
- `fake_token_ttl_seconds`：假令牌有效期（默认：`900`）
- `enable_auto_sandbox_workspace_prepare`：自动准备沙盒工作区（默认：`true`）
- `sandbox_workspace_root`：沙盒工作区根路径（默认：`/tmp/github-workspaces`）
- `sandbox_workspace_clone_depth`：沙盒克隆深度（默认：`1`）
- `enforce_tool_write_guard`：启用命令与脚本令牌字面量防护（默认：`false`）
- `guard_block_token_literal`：拦截明文令牌字面量（默认：`true`）

#### 3.2 上传私钥文件
1. 在插件配置页面，找到 `private_key_files` 配置项
2. 点击上传按钮，选择之前保存的 `.pem` 私钥文件
3. 保存配置

### 步骤 4：配置 Webhook

#### 4.1 获取 Webhook UUID
1. 在 AstrBot 管理界面，进入 **平台管理**
2. 找到 `github_app` 平台
3. 创建github app并且填入配置项
4. 保存并且关闭编辑页面，开始统一webhok模式
5. 复制 `webhook_uuid` 值

#### 4.2 更新 GitHub App Webhook URL
1. 返回 GitHub App 设置页面
2. 修改 **Webhook URL** 为你刚刚获取的统一webhook url：
   ```
   http://<你的服务器IP>:6185/api/platform/webhook/{webhook_uuid}
   ```
3. 保存更改

### 步骤 5：测试部署

#### 5.1 测试 Webhook 连接
1. 在 GitHub App 设置页面，滚动到 **Webhook URL** 下方
2. 点击 **Redeliver** 重新发送最近的 Webhook
3. 检查 AstrBot 日志，确认收到 `ping` 事件

#### 5.2 测试 Issue 评论
1. 在已安装应用的仓库中创建一个新 Issue
2. 在 Issue 中 @提及你的 bot（如 `@my-bot`）
3. 检查 AstrBot 是否收到事件并生成回复
4. 确认回复是否成功发布到 GitHub

#### 5.3 测试仓库操作工具
在 Issue 或 PR 评论中测试以下命令：

```
@my-bot 请列出仓库根目录
```

Bot 应该调用 `github_repo_ls` 工具并返回目录列表。

```
@my-bot 请读取 README.md 文件的前 50 行
```

Bot 应该调用 `github_repo_read` 工具并返回文件内容。

```
@my-bot 搜索包含 "TODO" 的代码
```

Bot 应该调用 `github_repo_search` 工具并返回搜索结果。

### 步骤 6：高级配置（可选）

#### 6.1 配置反向代理
如果使用 Nginx 反向代理：

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location /api/platform/webhook {
        proxy_pass http://127.0.0.1:6185;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

#### 6.2 配置防火墙
确保防火墙允许 Webhook 端口：

```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 6185/tcp

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-port=6185/tcp
sudo firewall-cmd --reload
```

#### 6.3 配置日志
在 AstrBot 配置中启用详细日志：

```yaml
logging:
  level: DEBUG
  handlers:
    - file
    - console
```

## 安全模型详解

### 假令牌桥接机制
1. **生成假令牌**：为每个 GitHub 会话生成短期假令牌（如 `ghu_fake_xxx`）
2. **注入上下文**：将假令牌注入 LLM 系统提示词
3. **工具执行前替换**：在 shell/python 工具执行前，将假令牌替换为真实只读令牌
4. **自动过期**：假令牌和映射关系在指定时间后自动清理

### 沙盒工作区
1. **自动克隆**：首次访问仓库时自动克隆到沙盒目录
2. **会话隔离**：每个会话有独立的工作区路径
3. **深度克隆**：可配置克隆深度，节省空间
4. **自动更新**：工作区不存在或无效时自动重新克隆

### 令牌防护
- **可选防护**：默认不启用，避免影响正常使用
- **字面量检测**：检测 `ghs_xxx` 格式的明文令牌
- **执行拦截**：在工具执行前拦截并替换为安全提示

## 工具使用说明

### github_repo_ls
列出仓库目录的一层文件列表。

**参数：**
- `repo`：目标仓库，格式 `owner/repo`
- `path`：目录路径，默认 `.`
- `ref`：分支/标签/提交，可选
- `offset`：分页偏移，默认 `0`
- `limit`：分页大小，默认 `50`
- `platform_id`：平台 ID，多平台时指定

**示例：**
```
@bot 列出 astrbot_plugin_githubapp-adapter 仓库的 src 目录
```

### github_repo_read
按行读取仓库文件内容。

**参数：**
- `repo`：目标仓库，格式 `owner/repo`
- `path`：文件路径，如 `README.md`
- `ref`：分支/标签/提交，可选
- `start_line`：起始行号（1-based），默认 `1`
- `max_lines`：读取行数，默认 `200`
- `platform_id`：平台 ID，多平台时指定

**示例：**
```
@bot 读取 astrbot_plugin_githubapp-adapter 的 README.md 前 100 行
```

### github_repo_search
在仓库内按关键字搜索代码。

**参数：**
- `repo`：目标仓库，格式 `owner/repo`
- `query`：搜索关键词
- `path`：限制搜索路径，可选
- `limit`：返回条数，默认 `20`
- `platform_id`：平台 ID，多平台时指定

**示例：**
```
@bot 在 astrbot_plugin_githubapp-adapter 中搜索 "TODO" 相关代码
```

## 故障排查

### 常见问题

#### Webhook 无法接收
1. 检查服务器端口是否开放
2. 检查 Webhook URL 是否正确
3. 检查 `github_webhook_secret` 是否匹配
4. 查看 AstrBot 日志确认是否有请求到达

#### 无法回复评论
1. 检查 GitHub App 是否有 Issues/PR 写权限
2. 检查私钥文件是否正确上传
3. 检查 `github_app_id` 是否正确
4. 查看日志中的错误详情

#### 工具调用失败
1. 检查仓库是否已安装 GitHub App
2. 检查 `enable_fake_token_bridge` 是否启用
3. 检查沙盒工作区目录权限
4. 查看工具返回的具体错误信息

#### 图片无法显示
1. 检查网络是否能访问 GitHub 图片 URL
2. 检查 `github_image_local_paths` 配置
3. 尝试使用 CDN 加速地址

### 日志分析

启用 DEBUG 日志后，关注以下关键字：
- `[GitHubApp]`：插件相关日志
- `webhook_callback`：Webhook 接收处理
- `issue_readonly_token`：令牌申请
- `list_repo_dir`：目录浏览
- `read_repo_file`：文件读取
- `search_repo_code`：代码搜索

## 配置示例

### 最小配置
```json
{
  "github_app_id": "123456",
  "github_webhook_secret": "your-secret-here",
  "private_key_files": ["files/astrbot-github-app.private-key.pem"]
}
```

### 完整配置
```json
{
  "github_app_id": "123456",
  "github_webhook_secret": "your-secret-here",
  "github_api_base_url": "https://api.github.com",
  "github_events": ["issues", "pull_request", "push"],
  "wake_event_types": ["issues", "pull_request"],
  "wake_on_mentions": true,
  "mention_target_logins": ["my-bot"],
  "ignore_bot_sender_events": true,
  "github_signature_validation": true,
  "github_delivery_cache_ttl_seconds": 900,
  "github_delivery_cache_max_entries": 10000,
  "private_key_files": ["files/astrbot-github-app.private-key.pem"],
  "default_github_events": [],
  "default_wake_event_types": ["issues", "pull_request"],
  "default_wake_on_mentions": true,
  "default_mention_target_logins": [],
  "default_ignore_bot_sender_events": true,
  "enable_signature_validation": true,
  "delivery_cache_ttl_seconds": 900,
  "delivery_cache_max_entries": 10000,
  "auto_create_github_skill": true,
  "github_skill_name": "github_app_ops",
  "overwrite_github_skill": true,
  "enable_fake_token_bridge": true,
  "fake_token_ttl_seconds": 900,
  "enable_auto_sandbox_workspace_prepare": true,
  "sandbox_workspace_root": "/tmp/github-workspaces",
  "sandbox_workspace_clone_depth": 1,
  "enforce_tool_write_guard": false,
  "guard_block_token_literal": true
}
```

## 开发说明

### 项目结构
```
astrbot_plugin_githubapp-adapter/
├── __init__.py
├── main.py                          # 插件主入口
├── metadata.yaml                    # 插件元数据
├── _conf_schema.json               # 配置模式
├── README.md                        # 本文档
├── adapter/
│   ├── __init__.py
│   ├── github_app_adapter.py       # GitHub App 适配器
│   ├── github_event.py             # 事件解析
│   ├── github_event_message.py     # 消息事件
│   ├── security.py                 # 安全工具
│   └── session_routing.py          # 会话路由
└── workflow/
    ├── __init__.py
    └── sandbox_workspace.py        # 沙盒工作区
```

### 核心类
- `GitHubAppAdapterPlugin`：插件主类，提供工具和事件处理
- `GitHubAppAdapter`：平台适配器，处理 Webhook 和 API 调用
- `GitHubParsedEvent`：解析后的 GitHub 事件
- `DeliveryDeduplicator`：Webhook 去重器

### 扩展开发
如需添加新工具，在 `main.py` 中使用 `@filter.llm_tool()` 装饰器：

```python
@filter.llm_tool(name="my_custom_tool")
async def my_custom_tool(
    self,
    event: AstrMessageEvent,
    param1: str = "",
) -> str:
    """工具说明"""
    # 实现逻辑
    return "结果"
```

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 更新日志

### v0.2.0
- 初始版本发布
- 支持 GitHub App Webhook 适配
- 提供安全的仓库操作工具
- 实现假令牌桥接机制
- 支持沙盒工作区自动准备
- 支持图片附件处理

## 联系方式

- 项目地址：https://github.com/example/astrbot_plugin_githubapp-adapter
- 问题反馈：https://github.com/example/astrbot_plugin_githubapp-adapter/issues
