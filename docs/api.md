## API 设计文档（v0：原型阶段）

### 约定
- **Base URL**：开发环境建议通过前端代理访问（`/api`），生产环境由网关/反向代理统一转发。
- **数据格式**：JSON（UTF-8）。
- **时间字段**：后续统一使用 ISO8601 字符串。
- **错误返回**：原型阶段先使用 `message + error`，后续会统一成 `code/message/data/traceId`。

---

## 0. 健康检查

### GET `/api/health`
用于前端/部署环境检查后端是否可用。

**Response 200**

```json
{ "ok": true }
```

---

## 1. 数据管理（合约上传/预处理）

### POST `/api/contracts/preprocess`
对合约源码做“冗余去除”的预处理，返回预处理后源码、以及行数统计信息。

**说明（当前实现）**
- 去除：SPDX 行、`pragma solidity ...;`、行注释 `//`、块注释 `/* ... */`、多余空行、行尾空白。
- 这是“可运行的最小版本”，后续会引入 AST/更精细规则（例如 import/using 等保留策略）。

**Request**

```json
{
  "source": "contract C { /* ... */ }",
  "filename": "a.sol"
}
```

字段说明：
- **source**（必填）：Solidity 源码全文
- **filename**（可选）：文件名（便于后续存储/审计/列表展示）

**Response 200**

```json
{
  "original": { "source": "原始源码", "lines": 120 },
  "processed": { "source": "预处理后源码", "lines": 80 },
  "removedLines": 40,
  "compressionRatio": 0.6666667
}
```

字段说明：
- **removedLines**：`original.lines - processed.lines`
- **compressionRatio**：`processed.lines / original.lines`

**Response 400**

```json
{
  "message": "参数错误",
  "error": "Key: 'preprocessRequest.Source' Error:Field validation for 'Source' failed on the 'required' tag"
}
```

---

## 2. 提示模板配置（规划）

> 该模块后续落地时会补齐：模板 CRUD、标签映射规则 CRUD、模板与规则绑定关系。

建议接口（规划）：
- GET `/api/prompts`
- POST `/api/prompts`
- PUT `/api/prompts/:id`
- DELETE `/api/prompts/:id`
- GET `/api/prompt-mappings?promptId=...`
- POST `/api/prompt-mappings`

---

## 3. 小样本训练（规划）

建议接口（规划）：
- POST `/api/train/jobs`：提交训练任务
- GET `/api/train/jobs/:id`：查询状态（running/success/failed）
- GET `/api/train/jobs/:id/metrics`：曲线数据（loss/acc/f1）
- GET `/api/models`：模型列表
- POST `/api/models/:id/load`：加载模型

---

## 4. 漏洞检测（规划）

建议接口（规划）：
- POST `/api/detect`：单份检测（支持返回漏洞位置/置信度）
- POST `/api/detect/batch`：批量检测（异步 job）
- GET `/api/detect/jobs/:id`：查询批量检测进度与结果

---

## 5. 对抗攻击与鲁棒性（规划）

建议接口（规划）：
- POST `/api/attack/generate`：生成对抗样本
- POST `/api/robust/evaluate`：鲁棒性评估（异步 job）
- GET `/api/robust/jobs/:id`：评估进度与指标
- POST `/api/robust/adversarial-train`：对抗训练

