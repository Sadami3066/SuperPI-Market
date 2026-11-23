# SuperPI Market

[English](README.md) | 简体中文

[SuperPI](https://github.com/Sadami3066/SuperPI) 官方插件、技能与远程 MCP 市场仓库。本仓库只维护 **ECDSA 签名索引**（`https://sadami3066.github.io/SuperPI-Market/registry.json`）与 Release 制品分发，不包含客户端源码。

## 三步提交上架 PR

前置要求：Node.js ≥ 22 与 `git`（无第三方 npm 依赖）。

1. **编写条目清单**：参考 `entries/sample.json`，在 `entries/plugin/`、`entries/skill/` 或 `entries/mcp/` 下新建 JSON：
   - 填写完整中英双语 `name` / `summary` / `description` / `tags`、全局唯一 `id` 与版本号 `version`；
   - 插件条目需声明 `plugin.apiLevel = 7`、`plugin.minHostVersion >= "2.0.0"`、`plugin.publisherKeyId`（`ed25519:...`）及真实的 `plugin.requiredAccess`（`normal` / `adb` / `root`）；
   - 将图标放入 `icons/<name>.png`（≤ 128 KB）；插件预览图可放 `previews/`，使用 `https://raw.githubusercontent.com/Sadami3066/SuperPI-Market/master/previews/<file>` 引用。
2. **填写制品校验值**：为公开可下载的 `.ddp`（≤ 50 MB）或技能 `.zip`（≤ 20 MB）计算 `sha256sum` 与字节 `size`。
3. **本地校验并提交 PR**：

```bash
node scripts/publish.mjs
node scripts/validate.mjs --no-sig
```

PR 会自动运行 `validate.yml` 格式校验；维护者依据 [上架审查清单](https://github.com/Sadami3066/SuperPI/blob/main/docs/plugins/pr-review.md) 与 [市场治理政策](https://github.com/Sadami3066/SuperPI/blob/main/docs/plugins/market-policy.md) 合并到 `master` 后，`release.yml` 自动签名部署到 GitHub Pages 并回读验证。

## 目录结构

| 路径 | 说明 |
|---|---|
| `entries/{plugin,skill,mcp}/` | 条目源清单（`registry.json` 由脚本生成，勿手改或提交） |
| `icons/` · `previews/` | 图标资源与插件竖版预览图 |
| `keys/market-public.pem` | 市场验签公钥（私钥仅存 CI Secret，不入库） |
| `scripts/` | `publish.mjs`、`validate.mjs`、`sign.mjs`、`verify-ddp.mjs` |
| `.github/workflows/` | PR 格式校验、Pages 签名部署与每日全量制品巡检 |

## 相关链接与许可

- 主仓库与插件开发指南：[Sadami3066/SuperPI](https://github.com/Sadami3066/SuperPI) · [插件开发文档](https://github.com/Sadami3066/SuperPI/blob/main/docs/plugins/README.md)
- 上架、下架或条目修改请提交 Issue / PR；安全问题请私下反馈。脚本与工作流采用 [Apache-2.0](LICENSE) 开源。
