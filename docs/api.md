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

> 本模块用于管理提示调优所需的 **提示模板（硬/软）** 与 **标签词映射规则（verbalizer）**，供后续训练/检测/鲁棒性评估复用与追溯。

### 2.1 GET `/api/prompts`
查询模板列表。

Query 参数（可选）：
- `type`: `hard` / `soft`
- `active`: `true`（仅返回启用模板）

**Response 200**

```json
[
  {
    "id": "uuid",
    "name": "Hard Prompt v1",
    "type": "hard",
    "description": "用于二分类提示调优",
    "templateText": "The code [X] is [MASK].",
    "softConfigJson": "",
    "isPreset": false,
    "isActive": true,
    "createdAt": "2026-03-12T10:00:00Z",
    "updatedAt": "2026-03-12T10:00:00Z"
  }
]
```

---

### 2.2 POST `/api/prompts`
创建模板。

**Request**

```json
{
  "name": "Hard Prompt v1",
  "type": "hard",
  "description": "用于二分类提示调优",
  "templateText": "The code [X] is [MASK].",
  "softConfigJson": "",
  "isActive": true
}
```

说明：
- `type=hard` 时要求 `templateText` **必须包含** `[X]`
- `type=soft` 时推荐把软提示参数写在 `softConfigJson`（JSON 字符串）

**Response 201**：返回创建后的模板对象（同上结构）

---

### 2.3 PUT `/api/prompts/:id`
更新模板（部分字段可选）。

**Request**

```json
{
  "name": "Hard Prompt v2",
  "description": "更新描述",
  "templateText": "The code [X] is [MASK].",
  "isActive": true
}
```

**Response 200**：返回更新后的模板对象

---

### 2.4 DELETE `/api/prompts/:id`
删除模板（会同时删除该模板下的映射规则）。

**Response 204**：无返回体

---

### 2.5 GET `/api/prompt-mappings?promptId=...`
查询指定模板的标签词映射列表。

**Response 200**

```json
[
  {
    "id": "uuid",
    "promptId": "prompt-uuid",
    "token": "bad",
    "label": "vulnerable",
    "isDefault": true,
    "createdAt": "2026-03-12T10:00:00Z",
    "updatedAt": "2026-03-12T10:00:00Z"
  }
]
```

说明：
- `label=vulnerable` 表示“有漏洞”
- `label=nonVulnerable` 表示“无漏洞”

---

### 2.6 POST `/api/prompt-mappings`
创建映射规则。

**Request**

```json
{
  "promptId": "prompt-uuid",
  "token": "good",
  "label": "nonVulnerable",
  "isDefault": true
}
```

**Response 201**：返回创建后的映射对象

---

### 2.7 PUT `/api/prompt-mappings/:id`
更新映射规则（部分字段可选）。

**Request**

```json
{
  "token": "bad",
  "label": "vulnerable",
  "isDefault": true
}
```

**Response 200**：返回更新后的映射对象

---

### 2.8 DELETE `/api/prompt-mappings/:id`
删除映射规则。

**Response 204**：无返回体

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

