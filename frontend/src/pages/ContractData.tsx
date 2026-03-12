import { useMemo, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Divider,
  Input,
  Row,
  Space,
  Statistic,
  Tabs,
  Typography,
  Upload,
  message,
} from "antd";
import type { UploadFile } from "antd";
import { InboxOutlined } from "@ant-design/icons";
import { DiffEditor } from "@monaco-editor/react";
import {
  preprocessContract,
  type PreprocessResponse,
} from "../services/contracts";
import { countLines, tryParseSolidity } from "../utils/solidity";

const MAX_FILES = 20;
const MAX_SIZE_MB = 2;

function isSolFile(name?: string) {
  if (!name) return false;
  return name.toLowerCase().endsWith(".sol");
}

async function readFileAsText(file: File) {
  return await file.text();
}

function downloadTextAsFile(text: string, filename: string) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default function ContractData() {
  const [tab, setTab] = useState<"upload" | "paste">("upload");
  const [fileList, setFileList] = useState<UploadFile[]>([]);
  const [pasted, setPasted] = useState("");

  const [original, setOriginal] = useState("");
  const [processed, setProcessed] = useState("");
  const [stats, setStats] = useState<PreprocessResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [syntaxError, setSyntaxError] = useState<string | null>(null);

  const canRun = useMemo(() => {
    if (tab === "paste") return pasted.trim().length > 0;
    return fileList.length > 0;
  }, [fileList.length, pasted, tab]);

  const onRun = async () => {
    setSyntaxError(null);
    setStats(null);
    setProcessed("");

    let source = "";
    let filename: string | undefined;

    if (tab === "paste") {
      source = pasted;
    } else {
      const first = fileList[0];
      const raw = first?.originFileObj;
      if (!raw) {
        message.warning("请先选择文件");
        return;
      }
      filename = raw.name;
      source = await readFileAsText(raw as File);
    }

    setOriginal(source);

    // 基础语法校验（前端）
    const parsed = await tryParseSolidity(source);
    if (!parsed.ok) {
      setSyntaxError(parsed.message ?? "语法校验失败");
      return;
    }

    setBusy(true);
    try {
      const res = await preprocessContract({ source, filename });
      setProcessed(res.processed.source);
      setStats(res);
      message.success("预处理完成");
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e);
      message.error(`预处理失败：${errMsg}`);
    } finally {
      setBusy(false);
    }
  };

  const canExportProcessed = processed.trim().length > 0;

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Card
        bordered={false}
        style={{ borderRadius: 12 }}
        styles={{ body: { padding: 20 } }}
      >
        <Row gutter={[16, 16]} align="middle">
          <Col flex="auto">
            <Typography.Title
              level={3}
              style={{ marginTop: 0, marginBottom: 4 }}
            >
              合约预处理
            </Typography.Title>
            <Typography.Text type="secondary">
              支持 .sol 文件上传/文本粘贴、前端校验、预处理前后对比与统计信息
            </Typography.Text>
          </Col>
          <Col>
            <Space>
              <Button
                onClick={() => {
                  setOriginal("");
                  setProcessed("");
                  setStats(null);
                  setSyntaxError(null);
                  setPasted("");
                  setFileList([]);
                }}
              >
                清空
              </Button>
              <Button
                type="primary"
                loading={busy}
                disabled={!canRun}
                onClick={onRun}
              >
                开始预处理
              </Button>
            </Space>
          </Col>
        </Row>
        <Divider style={{ margin: "16px 0" }} />

        <Row gutter={[16, 16]}>
          <Col xs={24} lg={10}>
            <Tabs
              activeKey={tab}
              onChange={(k) => setTab(k as "upload" | "paste")}
              items={[
                {
                  key: "upload",
                  label: "文件上传",
                  children: (
                    <Space
                      direction="vertical"
                      size={12}
                      style={{ width: "100%" }}
                    >
                      <Upload.Dragger
                        multiple
                        accept=".sol"
                        fileList={fileList}
                        beforeUpload={(file) => {
                          if (!isSolFile(file.name)) {
                            message.error("仅支持 .sol 文件");
                            return Upload.LIST_IGNORE;
                          }
                          if (file.size > MAX_SIZE_MB * 1024 * 1024) {
                            message.error(`文件大小不能超过 ${MAX_SIZE_MB}MB`);
                            return Upload.LIST_IGNORE;
                          }
                          if (fileList.length >= MAX_FILES) {
                            message.error(`最多上传 ${MAX_FILES} 份合约`);
                            return Upload.LIST_IGNORE;
                          }
                          return false;
                        }}
                        onChange={(info) => {
                          const next = info.fileList.slice(-MAX_FILES);
                          setFileList(next);
                        }}
                        onRemove={() => {
                          setStats(null);
                          setProcessed("");
                          return true;
                        }}
                        showUploadList={{ showRemoveIcon: true }}
                        style={{ borderRadius: 12 }}
                      >
                        <p className="ant-upload-drag-icon">
                          <InboxOutlined />
                        </p>
                        <p className="ant-upload-text">
                          拖拽 .sol 文件到此处，或点击选择
                        </p>
                        <p className="ant-upload-hint">
                          支持批量，前端会校验扩展名/大小；当前原型默认对队列第一份进行预处理
                        </p>
                      </Upload.Dragger>
                    </Space>
                  ),
                },
                {
                  key: "paste",
                  label: "文本粘贴",
                  children: (
                    <Space
                      direction="vertical"
                      size={12}
                      style={{ width: "100%" }}
                    >
                      <Input.TextArea
                        value={pasted}
                        onChange={(e) => setPasted(e.target.value)}
                        placeholder="直接粘贴 Solidity 合约源码…"
                        autoSize={{ minRows: 10, maxRows: 18 }}
                        style={{ borderRadius: 12 }}
                      />
                      <Typography.Text
                        type="secondary"
                        style={{ fontSize: 12 }}
                      >
                        行数：{countLines(pasted)}
                      </Typography.Text>
                    </Space>
                  ),
                },
              ]}
            />

            {syntaxError ? (
              <Alert
                type="error"
                showIcon
                message="基础语法校验未通过"
                description={syntaxError}
              />
            ) : null}
          </Col>

          <Col xs={24} lg={14}>
            <Card
              bordered={false}
              style={{ borderRadius: 12, background: "#fafafa" }}
              styles={{ body: { padding: 16 } }}
            >
              <Row justify="end" style={{ marginBottom: 8 }}>
                <Space>
                  <Button
                    disabled={!canExportProcessed}
                    onClick={async () => {
                      try {
                        await navigator.clipboard.writeText(processed);
                        message.success("已复制预处理后代码");
                      } catch {
                        message.error("复制失败：浏览器未授权剪贴板权限");
                      }
                    }}
                  >
                    复制结果
                  </Button>
                  <Button
                    type="primary"
                    disabled={!canExportProcessed}
                    onClick={() => {
                      const base =
                        tab === "upload"
                          ? fileList[0]?.name?.replace(/\.sol$/i, "") ??
                            "contract"
                          : "pasted";
                      downloadTextAsFile(processed, `${base}.processed.sol`);
                    }}
                  >
                    下载 .sol
                  </Button>
                </Space>
              </Row>
              <Row gutter={[16, 12]}>
                <Col xs={12} sm={6}>
                  <Statistic
                    title="原始行数"
                    value={stats?.original.lines ?? countLines(original)}
                  />
                </Col>
                <Col xs={12} sm={6}>
                  <Statistic
                    title="处理后行数"
                    value={
                      stats?.processed.lines ??
                      (processed ? countLines(processed) : 0)
                    }
                  />
                </Col>
                <Col xs={12} sm={6}>
                  <Statistic
                    title="删除行数"
                    value={stats?.removedLines ?? 0}
                  />
                </Col>
                <Col xs={12} sm={6}>
                  <Statistic
                    title="压缩比例"
                    value={
                      stats
                        ? `${Math.round(stats.compressionRatio * 100)}%`
                        : "--"
                    }
                  />
                </Col>
              </Row>
              <Divider style={{ margin: "12px 0" }} />
              <div
                style={{
                  height: 520,
                  marginTop: 8,
                  borderRadius: 12,
                  overflow: "hidden",
                }}
              >
                <DiffEditor
                  language="sol"
                  original={original || " "}
                  modified={processed || " "}
                  options={{
                    renderSideBySide: true,
                    readOnly: true,
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                    fontSize: 13,
                    wordWrap: "on",
                  }}
                />
              </div>
            </Card>
          </Col>
        </Row>
      </Card>
    </Space>
  );
}
