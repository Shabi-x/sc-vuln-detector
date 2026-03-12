## 数据库设计（SQLite / v0 原型阶段）

> 目标：用一份清晰、可扩展的 SQLite 结构支撑「数据上传 → 预处理 → 提示调优训练 → 漏洞检测 → 对抗攻击 → 鲁棒性评估 → 报告导出 → 操作审计」全链路。
>
> 原型阶段先落地：**提示模板与标签映射**（`prompts`、`prompt_mappings`），其余表作为后续模块的结构规划与字段约定。

---

## 一、设计原则

- **可复现**：训练/检测/评估任务必须能记录当时使用的模板/映射/模型版本。
- **低耦合**：把“配置类”“数据类”“任务类”“产出类”“审计类”拆开，模块之间用 ID 关联。
- **可迁移**：先用 SQLite + GORM，后续迁移 MySQL/Postgres 时尽量只替换驱动与少量类型。
- **不冗余**：不把同一份大文本到处复制；必要时用“快照字段”记录关键配置（用于复现）。

---

## 二、现阶段已落地（可直接建表）

### 1) `prompts` 提示模板表

用途：存储硬提示模板（字符串）与软提示配置（参数 JSON），供训练/检测/鲁棒性模块选择与引用。

关键字段：
- `id`：主键（UUID 字符串）
- `name`：模板名称
- `type`：`hard` / `soft`
- `template_text`：硬提示模板文本（要求包含 `[X]`，可选包含 `[MASK]`）
- `soft_config_json`：软提示参数（JSON 字符串），例如 `{"promptLength":16,"init":"random"}`
- `is_preset`：是否预置模板（预置模板可限制删除）
- `is_active`：是否启用（下拉选择只展示启用项时会用到）
- `created_at` / `updated_at`

推荐约束（逻辑约束）：
- `type=hard` 时必须包含 `[X]`
- `type=soft` 时 `soft_config_json` 必须是合法 JSON（后续可加校验）

### 2) `prompt_mappings` 标签词映射表（Verbalizer）

用途：把模型输出的“标签词 token”（如 `bad`/`good`）映射成业务标签（有漏洞/无漏洞）。

关键字段：
- `id`：主键（UUID）
- `prompt_id`：外键（引用 `prompts.id`）
- `token`：标签词（如 `bad`、`good`）
- `label`：`vulnerable`（有漏洞）/ `nonVulnerable`（无漏洞）
- `is_default`：是否作为该模板的默认映射（便于切换模板时自动加载）
- `created_at` / `updated_at`

推荐约束（后续可加唯一索引）：
- `prompt_id + token` 唯一，避免同一模板下 token 重复

---

## 三、全项目视角的后续表规划（先不实现，但建议按此扩展）

> 下面是你整个系统落地时建议的“表分层”，便于你一开始就清晰管理数据库结构。你可以按模块逐步启用迁移。

### A. 数据类（合约/预处理/对抗样本）

#### `contracts`
- `id`
- `filename`
- `source`（原始源码，TEXT）
- `uploaded_at`
- `source_hash`（可选：去重/缓存）
- `note`（可选）

#### `contract_preprocess_runs`
- `id`
- `contract_id`
- `rule_version`（预处理规则版本号/配置快照）
- `processed_source`（TEXT；或存差量/路径）
- `stats_json`（行数、压缩率等）
- `created_at`

#### `adversarial_samples`
- `id`
- `base_contract_id`
- `strategy`（虚假调用链类型/不可达路径规则等）
- `source`（对抗样本源码）
- `diff_json`（可选：差异定位）
- `created_at`

### B. 配置类（模型/模板）

#### `models`
- `id`
- `name`
- `framework`（pytorch 等）
- `base_model`（codebert/codet5）
- `artifact_path`（模型文件路径/标识）
- `meta_json`（超参、训练数据摘要）
- `created_at`

### C. 任务类（异步 Job：训练/检测/评估）

通用建议：用一张 `jobs` + 多张结果表，或每类任务一张表。原型阶段建议**每类一张表更直观**。

#### `train_jobs`
- `id`
- `status`（queued/running/success/failed/canceled）
- `prompt_id`
- `model_id`（或 base_model）
- `params_json`（epoch/lr/batch_size 等）
- `metrics_json`（最后指标，曲线可另表）
- `log_path`（或 log_text）
- `created_at` / `updated_at`

#### `train_metrics`
- `id`
- `job_id`
- `step` / `epoch`
- `loss` / `acc` / `f1`
- `created_at`

#### `detect_jobs`（批量检测）
- `id`
- `status`
- `prompt_id`
- `model_id`
- `params_json`
- `result_json`（汇总）
- `created_at` / `updated_at`

#### `detect_results`
- `id`
- `job_id`
- `contract_id`
- `label`
- `confidence`
- `vuln_type`（可选：多漏洞）
- `locations_json`（漏洞行/片段定位）
- `elapsed_ms`

#### `robust_jobs`（鲁棒性评估）
- `id`
- `status`
- `model_id`
- `prompt_id`
- `attack_config_json`
- `metrics_json`（攻击成功率、准确率下降等）
- `created_at` / `updated_at`

### D. 产出类（报告）

#### `reports`
- `id`
- `type`（detect/robust）
- `ref_job_id`
- `format`（md/pdf）
- `content_md`（或 path）
- `created_at`

### E. 审计类（操作日志）

#### `audit_logs`
- `id`
- `action`（upload/preprocess/train/detect/attack/robust/export）
- `actor`（可选：用户/来源）
- `payload_json`（请求参数快照）
- `trace_id`
- `created_at`

---

## 四、落地与管理建议（macOS 可视化）

- SQLite 数据文件默认：`backend/data/app.db`（可通过环境变量 `DB_PATH` 修改）
- 可视化工具推荐：
  - **DB Browser for SQLite**：轻量、免费，适合毕设原型
  - **TablePlus**：体验好，后续换 MySQL/Postgres 也能继续用
  - **DBeaver**：免费且功能全，但偏重

