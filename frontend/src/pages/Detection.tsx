import { useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Card,
  Col,
  Divider,
  Empty,
  Progress,
  Radio,
  Row,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { listContracts, type ContractSummary } from "../services/contracts";
import {
  listPrompts,
  type Label,
  type Prompt,
} from "../services/prompts";
import { listModels, type TrainedModel } from "../services/training";
import {
  createDetectBatchJob,
  detectOne,
  getDetectBatchJob,
  type BatchDetectResult,
  type DetectJob,
  type DetectResult,
} from "../services/detection";
import { getPageCache, setPageCache } from "../utils/pageCache";

type Mode = "single" | "batch";
const DETECTION_CACHE_KEY = "page:detection";

const labelText: Record<Label, string> = {
  vulnerable: "有漏洞",
  nonVulnerable: "无漏洞",
};

export default function Detection() {
  const cachedState = getPageCache<{
    mode?: Mode;
    selectedPromptId?: string;
    selectedModelId?: string;
    selectedContractId?: string;
    selectedContractIds?: string[];
    singleResult?: DetectResult | null;
    currentJob?: DetectJob | null;
    batchResults?: BatchDetectResult[];
  }>(DETECTION_CACHE_KEY);

  const [mode, setMode] = useState<Mode>(cachedState?.mode ?? "single");
  const [loading, setLoading] = useState(false);
  const [contracts, setContracts] = useState<ContractSummary[]>([]);
  const [prompts, setPrompts] = useState<Prompt[]>([]);
  const [models, setModels] = useState<TrainedModel[]>([]);

  const [selectedPromptId, setSelectedPromptId] = useState<string | undefined>(
    cachedState?.selectedPromptId,
  );
  const [selectedModelId, setSelectedModelId] = useState<string | undefined>(
    cachedState?.selectedModelId,
  );
  const [selectedContractId, setSelectedContractId] = useState<string | undefined>(
    cachedState?.selectedContractId,
  );
  const [selectedContractIds, setSelectedContractIds] = useState<string[]>(
    cachedState?.selectedContractIds ?? [],
  );

  const [singleResult, setSingleResult] = useState<DetectResult | null>(
    cachedState?.singleResult ?? null,
  );
  const [currentJob, setCurrentJob] = useState<DetectJob | null>(
    cachedState?.currentJob ?? null,
  );
  const [batchResults, setBatchResults] = useState<BatchDetectResult[]>(
    cachedState?.batchResults ?? [],
  );
  const pollTimerRef = useRef<number | null>(null);

  const selectedContractName = useMemo(
    () =>
      contracts.find((c) => c.id === selectedContractId)?.name ??
      selectedContractId ??
      "",
    [contracts, selectedContractId],
  );

  useEffect(() => {
    const init = async () => {
      try {
        setLoading(true);
        const [cs, ps, ms] = await Promise.all([
          listContracts(),
          listPrompts({ active: true }),
          listModels(),
        ]);
        setContracts(cs);
        setPrompts(ps);
        setModels(ms);
        if (ps.length > 0) setSelectedPromptId(ps[0]!.id);
        if (ms.some((m) => m.isLoaded)) {
          setSelectedModelId(ms.find((m) => m.isLoaded)!.id);
        }
        if (cs.length > 0) {
          setSelectedContractId(cs[0]!.id);
          setSelectedContractIds([cs[0]!.id]);
        }
      } catch (e) {
        message.error(
          `初始化失败：${e instanceof Error ? e.message : String(e)}`,
        );
      } finally {
        setLoading(false);
      }
    };
    void init();
  }, []);

  useEffect(() => {
    setPageCache(DETECTION_CACHE_KEY, {
      mode,
      selectedPromptId,
      selectedModelId,
      selectedContractId,
      selectedContractIds,
      singleResult,
      currentJob,
      batchResults,
    });
  }, [
    mode,
    selectedPromptId,
    selectedModelId,
    selectedContractId,
    selectedContractIds,
    singleResult,
    currentJob,
    batchResults,
  ]);

  useEffect(() => {
    if (!currentJob || (currentJob.status !== "queued" && currentJob.status !== "running")) {
      return;
    }
    pollBatchJob(currentJob.id);
    return () => {
      if (pollTimerRef.current !== null) {
        window.clearTimeout(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
  }, [currentJob?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const getErrMsg = (e: unknown) => {
    if (typeof e === "object" && e !== null) {
      const resp = (
        e as { response?: { data?: { error?: string; message?: string } } }
      ).response;
      if (resp?.data?.error) return resp.data.error;
      if (resp?.data?.message) return resp.data.message;
    }
    return e instanceof Error ? e.message : String(e);
  };

  const pollBatchJob = (jobId: string) => {
    if (pollTimerRef.current !== null) {
      window.clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    const tick = async () => {
      try {
        const data = await getDetectBatchJob(jobId);
        setCurrentJob(data.job);
        setBatchResults(data.results);
        if (data.job.status === "queued" || data.job.status === "running") {
          pollTimerRef.current = window.setTimeout(tick, 1000);
        }
      } catch (e) {
        message.error(
          `获取任务状态失败：${e instanceof Error ? e.message : String(e)}`,
        );
      }
    };
    void tick();
  };

  const onDetectSingle = async () => {
    if (!selectedContractId || !selectedPromptId) {
      message.warning("请先选择合约与提示模板");
      return;
    }
    try {
      setLoading(true);
      const data = await detectOne({
        contractId: selectedContractId,
        promptId: selectedPromptId,
        modelId: selectedModelId || undefined,
      });
      setSingleResult(data.result);
      message.success("检测完成");
    } catch (e) {
      message.error(`检测失败：${getErrMsg(e)}`);
    } finally {
      setLoading(false);
    }
  };

  const onDetectBatch = async () => {
    if (!selectedPromptId || selectedContractIds.length === 0) {
      message.warning("请先选择模板和待测合约");
      return;
    }
    try {
      setLoading(true);
      const job = await createDetectBatchJob({
        contractIds: selectedContractIds,
        promptId: selectedPromptId,
        modelId: selectedModelId || undefined,
      });
      setCurrentJob(job);
      setBatchResults([]);
      message.success("批量检测任务已创建");
      pollBatchJob(job.id);
    } catch (e) {
      message.error(`创建任务失败：${getErrMsg(e)}`);
    } finally {
      setLoading(false);
    }
  };

  const progressPercent = useMemo(() => {
    if (!currentJob) return 0;
    let total = 0;
    try {
      const params = JSON.parse(currentJob.paramsJson) as {
        contractIds?: string[];
      };
      total = params.contractIds?.length ?? 0;
    } catch {
      total = 0;
    }
    if (total === 0) return 0;
    return Math.min(100, Math.round((batchResults.length / total) * 100));
  }, [currentJob, batchResults.length]);

  const batchColumns: ColumnsType<BatchDetectResult> = [
    {
      title: "合约",
      dataIndex: "contractId",
      render: (id: string) => contracts.find((c) => c.id === id)?.name ?? id,
    },
    {
      title: "结论",
      dataIndex: "label",
      width: 120,
      render: (l: Label) => (
        <Tag color={l === "vulnerable" ? "red" : "green"}>{labelText[l]}</Tag>
      ),
    },
    {
      title: "置信度",
      dataIndex: "confidence",
      width: 120,
      render: (v: number) => v.toFixed(4),
    },
    {
      title: "漏洞类型",
      dataIndex: "vulnType",
      width: 160,
      render: (s: string) => s || "--",
    },
    { title: "命中标签词", dataIndex: "matchedToken", width: 150 },
    { title: "耗时(ms)", dataIndex: "elapsedMs", width: 100 },
  ];

  const parsedJobSummary = useMemo(() => {
    if (!currentJob?.resultJson) return null;
    try {
      return JSON.parse(currentJob.resultJson) as {
        total?: number;
        success?: number;
        failed?: number;
        labelStats?: Partial<Record<Label, number>>;
        vulnTypeStats?: Record<string, number>;
      };
    } catch {
      return null;
    }
  }, [currentJob]);

  const exportCsv = () => {
    if (!batchResults.length) {
      message.info("当前没有可导出的批量检测结果");
      return;
    }
    const header = [
      "contractName",
      "contractId",
      "label",
      "confidence",
      "vulnType",
      "matchedToken",
      "elapsedMs",
      "jobId",
      "modelId",
      "promptId",
      "createdAt",
    ];
    const lines = batchResults.map((r) => {
      const name =
        contracts.find((c) => c.id === r.contractId)?.name ?? r.contractId;
      const cells = [
        name,
        r.contractId,
        r.label,
        r.confidence.toFixed(4),
        r.vulnType || "",
        r.matchedToken || "",
        String(r.elapsedMs),
        r.jobId,
        r.modelId,
        r.promptId,
        r.createdAt,
      ];
      return cells.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",");
    });
    const csv = [header.join(","), ...lines].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `detect-job-${currentJob?.id || "results"}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Card
        bordered={false}
        style={{ borderRadius: 12 }}
        styles={{ body: { padding: 20 } }}
      >
        <Row gutter={[16, 12]} align="middle">
          <Col flex="auto">
            <Typography.Title
              level={3}
              style={{ marginTop: 0, marginBottom: 4 }}
            >
              漏洞检测
            </Typography.Title>
            <Typography.Text type="secondary">
              使用已训练的目标漏洞二分类模型，对预处理合约执行单份或批量检测并输出是否存在目标漏洞的置信度结果。
            </Typography.Text>
          </Col>
        </Row>

        <Divider style={{ margin: "16px 0" }} />

        <Row gutter={16}>
          <Col xs={24} lg={8}>
            <Typography.Text type="secondary">检测模式</Typography.Text>
            <div style={{ marginTop: 8 }}>
              <Radio.Group
                value={mode}
                onChange={(e) => setMode(e.target.value as Mode)}
                optionType="button"
                buttonStyle="solid"
                options={[
                  { label: "单份检测", value: "single" },
                  { label: "批量检测", value: "batch" },
                ]}
              />
            </div>
          </Col>
          <Col xs={24} lg={8}>
            <Typography.Text type="secondary">提示模板</Typography.Text>
            <Select
              style={{ width: "100%", marginTop: 8 }}
              value={selectedPromptId}
              onChange={setSelectedPromptId}
              options={prompts.map((p) => ({ value: p.id, label: p.name }))}
              placeholder="选择模板"
            />
          </Col>
          <Col xs={24} lg={8}>
            <Typography.Text type="secondary">
              模型（默认已加载）
            </Typography.Text>
            <Select
              style={{ width: "100%", marginTop: 8 }}
              value={selectedModelId}
              onChange={setSelectedModelId}
              options={models.map((m) => ({
                value: m.id,
                label: `${m.name}${m.isLoaded ? "（已加载）" : ""}`,
              }))}
              placeholder="未选择时使用当前已加载模型"
              allowClear
            />
          </Col>
        </Row>

        <Divider style={{ margin: "16px 0" }} />

        {mode === "single" ? (
          <Space direction="vertical" size={12} style={{ width: "100%" }}>
            <Row gutter={[12, 12]} align="bottom">
              <Col xs={24} lg={18}>
                <Typography.Text type="secondary">待测合约</Typography.Text>
                <Select
                  style={{ width: "100%", marginTop: 8 }}
                  value={selectedContractId}
                  onChange={setSelectedContractId}
                  options={contracts.map((c) => ({ value: c.id, label: c.name }))}
                  placeholder="选择待测合约"
                  showSearch
                  optionFilterProp="label"
                />
              </Col>
              <Col xs={24} lg={6}>
                <Button
                  type="primary"
                  onClick={() => void onDetectSingle()}
                  loading={loading}
                  style={{ width: "100%" }}
                >
                  开始单份检测
                </Button>
              </Col>
            </Row>

            {singleResult ? (
              <Card
                size="small"
                style={{ borderRadius: 12, background: "#fafafa" }}
              >
                <Space direction="vertical" size={8}>
                  <Typography.Text>
                    合约：
                    <Typography.Text strong>
                      {selectedContractName}
                    </Typography.Text>
                  </Typography.Text>
                  <Space>
                    <Tag
                      color={
                        singleResult.label === "vulnerable" ? "red" : "green"
                      }
                    >
                      {labelText[singleResult.label]}
                    </Tag>
                    <Tag>置信度 {singleResult.confidence.toFixed(4)}</Tag>
                    <Tag>预测标签: {singleResult.matchedToken || "--"}</Tag>
                    {singleResult.vulnType ? (
                      <Tag color="orange">{singleResult.vulnType}</Tag>
                    ) : null}
                  </Space>
                  <Typography.Text type="secondary">
                    TopK:{" "}
                    {singleResult.topK
                      .map((x) => `${x.token}(${x.score.toFixed(4)})`)
                      .join(", ")}
                  </Typography.Text>
                </Space>
              </Card>
            ) : (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="暂无检测结果"
              />
            )}
          </Space>
        ) : (
          <Space direction="vertical" size={12} style={{ width: "100%" }}>
            <Row gutter={[12, 12]} align="bottom">
              <Col xs={24} lg={18}>
                <Typography.Text type="secondary">待批量检测合约</Typography.Text>
                <Select
                  mode="multiple"
                  style={{ width: "100%", marginTop: 8 }}
                  value={selectedContractIds}
                  onChange={setSelectedContractIds}
                  options={contracts.map((c) => ({ value: c.id, label: c.name }))}
                  placeholder="选择待批量检测合约"
                  showSearch
                  optionFilterProp="label"
                />
              </Col>
              <Col xs={24} lg={6}>
                <Button
                  type="primary"
                  onClick={() => void onDetectBatch()}
                  loading={loading}
                  style={{ width: "100%" }}
                >
                  启动批量检测
                </Button>
              </Col>
            </Row>

            {currentJob ? (
              <>
                <Card
                  size="small"
                  style={{ borderRadius: 12, background: "#fafafa" }}
                  styles={{ body: { padding: 12 } }}
                >
                  <Space
                    direction="vertical"
                    size={6}
                    style={{ width: "100%" }}
                  >
                    <Space
                      align="center"
                      style={{ width: "100%", justifyContent: "space-between" }}
                    >
                      <Typography.Text type="secondary">
                        当前任务：
                        <Typography.Text code>{currentJob.id}</Typography.Text>{" "}
                        状态：
                        {currentJob.status}
                      </Typography.Text>
                      <Button size="small" onClick={exportCsv}>
                        导出 CSV
                      </Button>
                    </Space>
                    <Progress
                      percent={progressPercent}
                      size="small"
                      status={
                        currentJob.status === "failed" ? "exception" : "active"
                      }
                    />
                    {parsedJobSummary ? (
                      <Space size={12} wrap>
                        <Typography.Text type="secondary">
                          总数：{parsedJobSummary.total ?? "--"}
                        </Typography.Text>
                        <Typography.Text type="secondary">
                          成功：{parsedJobSummary.success ?? 0} 失败：
                          {parsedJobSummary.failed ?? 0}
                        </Typography.Text>
                        {parsedJobSummary.labelStats ? (
                          <Typography.Text type="secondary">
                            有漏洞：
                            {parsedJobSummary.labelStats.vulnerable ?? 0}
                            ；无漏洞：
                            {parsedJobSummary.labelStats.nonVulnerable ?? 0}
                          </Typography.Text>
                        ) : null}
                      </Space>
                    ) : null}
                  </Space>
                </Card>
                <Table
                  rowKey="id"
                  size="small"
                  columns={batchColumns}
                  dataSource={batchResults}
                  pagination={{ pageSize: 8, hideOnSinglePage: true }}
                />
              </>
            ) : (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="暂无批量检测任务"
              />
            )}
          </Space>
        )}
      </Card>
    </Space>
  );
}
