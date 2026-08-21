# Smart Contract Vulnerability Detector

智能合约漏洞检测工具，前端 React + Ant Design，后端 Go (Gin)，检测模型基于 Python (PyTorch/Transformers)。

## 环境要求

- Node.js >= 18（推荐使用 pnpm）
- Go >= 1.23
- Python >= 3.10（仅训练/推理脚本需要）
- Git

## 快速开始

### 1. 克隆项目

```bash
git clone <repo-url>
cd sc-vuln-detector
```

### 2. 启动后端

新开一个终端：

```bash
cd backend
go run ./cmd/server
```

后端默认监听 `http://localhost:8080`。

### 3. 启动前端

再开一个终端：

```bash
cd frontend
pnpm install
pnpm dev
```

> 没有 pnpm 可用 `npm install && npm run dev` 代替。

前端默认运行在 `http://localhost:5173`，API 请求通过 Vite proxy 转发到后端 `localhost:8080`。

## 项目结构

```
sc-vuln-detector/
├── frontend/          # React + Vite + Ant Design + Monaco Editor
├── backend/           # Go + Gin + GORM/SQLite
│   └── cmd/server/    # 后端入口
├── python_scripts/    # 漏洞检测模型训练与推理
└── docs/              # 文档
```
