import { useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Card,
  Col,
  Divider,
  Empty,
  InputNumber,
  Progress,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Tabs,
  Tooltip,
  Typography,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { Column } from "@ant-design/plots";
import { listContracts, type ContractSummary } from "../services/contracts";
import { listPrompts, type Prompt } from "../services/prompts";
import { listModels, type TrainedModel } from "../services/training";
import {
  createRobustJob,
  getRobustJob,
  listRobustJobs,
  type RobustJob,
  type RobustMetrics,
} from "../services/robust";
import { getPageCache, setPageCache } from "../utils/pageCache";

const ATTACK_METHOD = {
  label: "DIP 黑盒对抗攻击",
  value: "dip-attack",
  steps: ["作用域感知变量重命名", "梯度估计位置选择", "死代码插入扰动"],
};
const ROBUSTNESS_CACHE_KEY = "page:robustness";
const VICTIM_MODEL_OPTIONS = [
  { label: "CodeBERT", value: "codebert" },
  { label: "AME", value: "AME" },
  { label: "GPSCVul", value: "GPSCVul" },
  { label: "ConvMHSA", value: "ConvMHSA" },
  { label: "Clear", value: "Clear" },
];

function formatFixed(value: unknown, digits: number, fallback = "--") {
  return typeof value === "number" && Number.isFinite(value)
    ? value.toFixed(digits)
    : fallback;
}

function formatPercent(value: unknown, digits = 2, fallback = "--") {
  return typeof value === "number" && Number.isFinite(value)
    ? `${(value * 100).toFixed(digits)}%`
    : fallback;
}

export default function Robustness() {
  const cachedState = getPageCache<{
    activeTab?: "run" | "history";
    selectedContractIds?: string[];
    selectedPromptId?: string;
    selectedModelId?: string;
    selectedVictimModels?: string[];
    activeVictimModel?: string;
    variantsPerSource?: number;
    currentJob?: RobustJob | null;
    metrics?: RobustMetrics | null;
  }>(ROBUSTNESS_CACHE_KEY);

  const [activeTab, setActiveTab] = useState<"run" | "history">(
    cachedState?.activeTab ?? "run",
  );
  const [contracts, setContracts] = useState<ContractSummary[]>([]);
  const [prompts, setPrompts] = useState<Prompt[]>([]);
  const [models, setModels] = useState<TrainedModel[]>([]);
  const [historyJobs, setHistoryJobs] = useState<RobustJob[]>([]);

  const [selectedContractIds, setSelectedContractIds] = useState<string[]>(
    cachedState?.selectedContractIds ?? [],
  );
  const [selectedPromptId, setSelectedPromptId] = useState<string | undefined>(
    cachedState?.selectedPromptId,
  );
  const [selectedModelId, setSelectedModelId] = useState<string | undefined>(
    cachedState?.selectedModelId,
  );
  const [selectedVictimModels, setSelectedVictimModels] = useState<string[]>(
    cachedState?.selectedVictimModels ?? VICTIM_MODEL_OPTIONS.map((item) => item.value),
  );
  const [activeVictimModel, setActiveVictimModel] = useState<string | undefined>(
    cachedState?.activeVictimModel ?? "codebert",
  );
  const [variantsPerSource, setVariantsPerSource] = useState(
    cachedState?.variantsPerSource ?? 1,
  );

  const [loading, setLoading] = useState(false);
  const [currentJob, setCurrentJob] = useState<RobustJob | null>(
    cachedState?.currentJob ?? null,
  );
  const [metrics, setMetrics] = useState<RobustMetrics | null>(
    cachedState?.metrics ?? null,
  );
  const pollTimerRef = useRef<number | null>(null);

  useEffect(() => {
    const init = async () => {
      try {
        setLoading(true);
        const [cs, ps, ms, hs] = await Promise.all([
          listContracts(),
          listPrompts({ active: true }),
          listModels(),
          listRobustJobs(),
        ]);
        setContracts(cs);
        setPrompts(ps);
        setModels(ms);
        setHistoryJobs(hs);
        if (cs.length > 0 && (!cachedState?.selectedContractIds || cachedState.selectedContractIds.length === 0)) {
          setSelectedContractIds([cs[0]!.id]);
        }
        if (ps.length > 0 && !cachedState?.selectedPromptId) setSelectedPromptId(ps[0]!.id);
        const loaded = ms.find((m) => m.isLoaded);
        if (loaded && !cachedState?.selectedModelId) setSelectedModelId(loaded.id);
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
    setPageCache(ROBUSTNESS_CACHE_KEY, {
      activeTab,
      selectedContractIds,
      selectedPromptId,
      selectedModelId,
      selectedVictimModels,
      activeVictimModel,
      variantsPerSource,
      currentJob,
      metrics,
    });
  }, [
    activeTab,
    selectedContractIds,
    selectedPromptId,
    selectedModelId,
    selectedVictimModels,
    activeVictimModel,
    variantsPerSource,
    currentJob,
    metrics,
  ]);

  useEffect(() => {
    if (!currentJob || (currentJob.status !== "queued" && currentJob.status !== "running")) {
      return;
    }
    pollJob(currentJob.id);
    return () => {
      if (pollTimerRef.current !== null) {
        window.clearTimeout(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
  }, [currentJob?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const victimResults = metrics?.victimResults ?? [];
    if (victimResults.length === 0) {
      return;
    }
    if (!activeVictimModel || !victimResults.some((item) => item.victimModel === activeVictimModel)) {
      setActiveVictimModel(victimResults[0]!.victimModel);
    }
  }, [metrics, activeVictimModel]);

  const refreshHistory = async () => {
    try {
      const hs = await listRobustJobs();
      setHistoryJobs(hs);
    } catch (e) {
      message.error(
        `加载历史任务失败：${e instanceof Error ? e.message : String(e)}`,
      );
    }
  };

  const pollJob = (jobId: string) => {
    if (pollTimerRef.current !== null) {
      window.clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    const tick = async () => {
      try {
        const data = await getRobustJob(jobId);
        setCurrentJob(data.job);
        setMetrics(data.metrics ?? null);
        if (data.job.status === "queued" || data.job.status === "running") {
          pollTimerRef.current = window.setTimeout(tick, 1000);
        }
      } catch (e) {
        message.error(
          `获取鲁棒性任务失败：${e instanceof Error ? e.message : String(e)}`,
        );
      }
    };
    void tick();
  };

  const onStart = async () => {
    if (
      !selectedModelId ||
      !selectedPromptId ||
      selectedContractIds.length === 0
    ) {
      message.warning("请先选择模型、提示模板和合约");
      return;
    }
    try {
      setLoading(true);
      const job = await createRobustJob({
        modelId: selectedModelId,
        promptId: selectedPromptId,
        contractIds: selectedContractIds,
        victimModels: selectedVictimModels,
        strategies: [ATTACK_METHOD.value],
        variantsPerSource,
      });
      setCurrentJob(job);
      setMetrics(null);
      message.success("鲁棒性评估任务已创建");
      await refreshHistory();
      pollJob(job.id);
    } catch (e) {
      message.error(
        `创建任务失败：${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setLoading(false);
    }
  };

  const progressPercent = useMemo(() => {
    if (!currentJob?.startedAt || !currentJob.finishedAt) {
      if (currentJob?.status === "success" || currentJob?.status === "failed")
        return 100;
      if (currentJob?.status === "running") return 50;
      return 0;
    }
    return 100;
  }, [currentJob]);

  const activeVictim = useMemo(
    () =>
      metrics?.victimResults?.find((item) => item.victimModel === activeVictimModel) ??
      metrics?.victimResults?.[0],
    [metrics, activeVictimModel],
  );

  const supportedVictims = useMemo(
    () => (metrics?.victimResults ?? []).filter((item) => item.supported),
    [metrics],
  );

  const queryComparisonData = useMemo(() => {
    return supportedVictims
      .filter((item) => (item.avgQueries ?? 0) > 0)
      .map((item) => ({
        victim: item.displayName,
        value: Number((item.avgQueries ?? 0).toFixed(2)),
      }));
  }, [supportedVictims]);

  const codebleuComparisonData = useMemo(() => {
    return supportedVictims
      .filter((item) => (item.avgCodeBLEU ?? 0) > 0)
      .map((item) => ({
        victim: item.displayName,
        value: Number((item.avgCodeBLEU ?? 0).toFixed(4)),
      }));
  }, [supportedVictims]);

  const showQueryChart = queryComparisonData.length >= 2;
  const showCodebleuChart = codebleuComparisonData.length >= 2;

  const perContractRows = useMemo(() => activeVictim?.perContract ?? [], [activeVictim]);
  const attackSuccessRateText = formatPercent(activeVictim?.attackSuccessRate);
  const accuracyDropRateText = formatPercent(activeVictim?.accuracyDropRate);
  const avgDropText = formatFixed(activeVictim?.avgConfidenceDrop, 4);
  const avgQueriesText = formatFixed(activeVictim?.avgQueries, 2);
  const avgPerturbationRateText = formatPercent(activeVictim?.avgPerturbationRate);
  const avgVisiblePerturbationRateText = formatPercent(activeVictim?.avgVisiblePerturbationRate);
  const avgCodeBLEUText = formatFixed(activeVictim?.avgCodeBLEU, 4);
  const queryBudgetHitsText =
    typeof activeVictim?.queryBudgetHits === "number"
      ? `${activeVictim.queryBudgetHits}`
      : "--";
  const formatSkippedReason = (reason?: string) => {
    if (!reason) return "--";
    if (reason.includes("原始样本未被模型判定为目标漏洞")) {
      return "该合约的原始检测结果为“无漏洞”，因此本次不进入攻击成功率统计。";
    }
    return reason;
  };

  const labelTag = (l: string) => {
    if (l === "vulnerable") return <Tag color="red">有漏洞</Tag>;
    if (l === "nonVulnerable") return <Tag color="green">无漏洞</Tag>;
    return <Tag>{l}</Tag>;
  };

  const contractColumns: ColumnsType<
    NonNullable<RobustMetrics["perContract"]>[number]
  > = [
    {
      title: "合约",
      dataIndex: "contractName",
      width: 180,
      render: (v: string, r) => (
        <Space orientation="vertical" size={2} style={{ width: "100%" }}>
          <Tooltip title={v}>
            <Typography.Text
              strong
              style={{
                maxWidth: 140,
                display: "inline-block",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
                verticalAlign: "bottom",
              }}
            >
              {v}
            </Typography.Text>
          </Tooltip>
          <Tooltip title={r.baseContractId}>
            <Typography.Text
              type="secondary"
              style={{
                fontSize: 12,
                maxWidth: 140,
                display: "inline-block",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
                verticalAlign: "bottom",
              }}
            >
              {r.baseContractId}
            </Typography.Text>
          </Tooltip>
        </Space>
      ),
    },
    {
      title: "原始预测",
      width: 140,
      render: (_, r) => (
        <Space size={8}>
          {labelTag(r.origLabel)}
          <Typography.Text type="secondary">
            {formatFixed(r.origConfidence, 4)}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: "对抗样本",
      width: 120,
      render: (_, r) => (
        <Typography.Text type="secondary">{r.advTotal} 条</Typography.Text>
      ),
    },
    {
      title: "成功次数",
      dataIndex: "flipped",
      width: 110,
      render: (v: number) => <Typography.Text>{v}</Typography.Text>,
    },
    {
      title: "DIP 攻击说明",
      width: 280,
      render: (_, r) => (
        <Space orientation="vertical" size={2}>
          {r.bestAttackSample ? (
            <>
              <Typography.Text type="secondary">
                最优变体 #{r.bestAttackSample.variantIndex}，查询 {r.bestAttackSample.queries} 次
              </Typography.Text>
              <Typography.Text type="secondary">
                可见扰动率 {formatPercent(r.bestAttackSample.visiblePerturbationRate)}，CodeBLEU {formatFixed(r.bestAttackSample.codebleu, 4)}
              </Typography.Text>
              <Typography.Text type="secondary">
                {r.bestAttackSample.queryBudgetHit ? "已打满查询预算，" : ""}置信度下降 {formatFixed(r.bestAttackSample.confidenceDrop, 4)}
              </Typography.Text>
            </>
          ) : (
            <Typography.Text type="secondary">
              {formatSkippedReason(r.skippedReason)}
            </Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: "平均查询次数",
      dataIndex: "avgQueries",
      width: 130,
      render: (v: number) => <Typography.Text>{formatFixed(v, 2)}</Typography.Text>,
    },
    {
      title: "可见扰动率",
      dataIndex: "avgVisiblePerturbationRate",
      width: 130,
      render: (v: number) => (
        <Typography.Text>{formatPercent(v)}</Typography.Text>
      ),
    },
    {
      title: "CodeBLEU",
      dataIndex: "avgCodeBLEU",
      width: 120,
      render: (v: number) => <Typography.Text>{formatFixed(v, 4)}</Typography.Text>,
    },
    {
      title: "预算命中",
      dataIndex: "queryBudgetHits",
      width: 110,
      render: (v: number) => <Typography.Text>{v} 次</Typography.Text>,
    },
    {
      title: "对抗平均置信度",
      dataIndex: "avgAdvConfidence",
      width: 150,
      render: (v: number) => <Typography.Text>{formatFixed(v, 4)}</Typography.Text>,
    },
    {
      title: "平均置信度下降",
      dataIndex: "avgConfDrop",
      width: 150,
      render: (v: number) => <Typography.Text>{formatFixed(v, 4)}</Typography.Text>,
    },
  ];

  const victimColumns: ColumnsType<
    NonNullable<RobustMetrics["victimResults"]>[number]
  > = [
    {
      title: "受害模型",
      dataIndex: "displayName",
      width: 140,
      render: (v: string, r) => (
        <Button
          type={r.victimModel === activeVictim?.victimModel ? "primary" : "default"}
          size="small"
          onClick={() => setActiveVictimModel(r.victimModel)}
        >
          {v}
        </Button>
      ),
    },
    {
      title: "状态",
      width: 110,
      render: (_, r) =>
        r.supported ? <Tag color="green">可评估</Tag> : <Tag>暂不支持</Tag>,
    },
    {
      title: "攻击成功率",
      width: 120,
      render: (_, r) => formatPercent(r.attackSuccessRate),
    },
    {
      title: "准确率下降",
      width: 120,
      render: (_, r) => formatPercent(r.accuracyDropRate),
    },
    {
      title: "平均查询次数",
      width: 120,
      render: (_, r) => formatFixed(r.avgQueries, 2),
    },
    {
      title: "可见扰动率",
      width: 120,
      render: (_, r) => formatPercent(r.avgVisiblePerturbationRate),
    },
    {
      title: "CodeBLEU",
      width: 100,
      render: (_, r) => formatFixed(r.avgCodeBLEU, 4),
    },
  ];

  const historyColumns: ColumnsType<RobustJob> = [
    {
      title: "任务ID",
      dataIndex: "id",
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: "状态",
      dataIndex: "status",
      width: 110,
      render: (s: RobustJob["status"]) => (
        <Tag
          color={
            s === "success" ? "green" : s === "failed" ? "red" : "processing"
          }
        >
          {s}
        </Tag>
      ),
    },
    {
      title: "模型",
      dataIndex: "modelId",
      width: 220,
      render: (id: string) => models.find((m) => m.id === id)?.name ?? id,
    },
    {
      title: "模板",
      dataIndex: "promptId",
      width: 220,
      render: (id: string) => prompts.find((p) => p.id === id)?.name ?? id,
    },
    { title: "创建时间", dataIndex: "createdAt", width: 180 },
    {
      title: "操作",
      width: 120,
      render: (_, r) => (
        <Button
          size="small"
          onClick={async () => {
            try {
              const data = await getRobustJob(r.id);
              setCurrentJob(data.job);
              setMetrics(data.metrics ?? null);
              setActiveTab("run");
              message.success("已加载历史任务结果");
            } catch (e) {
              message.error(
                `加载任务失败：${e instanceof Error ? e.message : String(e)}`,
              );
            }
          }}
        >
          查看
        </Button>
      ),
    },
  ];

  return (
    <Space orientation="vertical" size={16} style={{ width: "100%" }}>
      <Card
        variant="borderless"
        style={{ borderRadius: 12 }}
        styles={{ body: { padding: 20 } }}
      >
        <Row gutter={[16, 12]} align="middle">
          <Col flex="auto">
            <Typography.Title
              level={3}
              style={{ marginTop: 0, marginBottom: 4 }}
            >
              对抗攻击与鲁棒性
            </Typography.Title>
            <Typography.Text type="secondary">
              基于 DIP 黑盒攻击流程生成对抗样本，并从攻击成功率、准确率下降、查询成本、可见扰动率与代码相似性等维度评估目标漏洞检测模型的鲁棒性。
            </Typography.Text>
          </Col>
        </Row>

        <Divider style={{ margin: "16px 0" }} />
        <Tabs
          activeKey={activeTab}
          onChange={(k) => setActiveTab(k as "run" | "history")}
          items={[
            { key: "run", label: "新建评估" },
            { key: "history", label: "历史评估记录" },
          ]}
        />

        {activeTab === "run" ? (
          <>
            <Card
              size="small"
              style={{ marginBottom: 16, borderRadius: 12, background: "#fafafa" }}
              styles={{ body: { padding: 14 } }}
            >
              <Space orientation="vertical" size={4} style={{ width: "100%" }}>
                <Typography.Text strong>攻击方法：{ATTACK_METHOD.label}</Typography.Text>
                <Typography.Text type="secondary">
                  执行流程：{ATTACK_METHOD.steps.join(" → ")}
                </Typography.Text>
                <Typography.Text type="secondary">
                  评估口径：仅统计原始预测为“有漏洞”的样本，并优先关注进入模型可见窗口的扰动、查询成本与代码相似性。
                </Typography.Text>
              </Space>
            </Card>

            <Row gutter={16}>
              <Col xs={24} lg={8}>
                <Typography.Text type="secondary">模型</Typography.Text>
                <Select
                  style={{ width: "100%", marginTop: 8 }}
                  value={selectedModelId}
                  onChange={setSelectedModelId}
                  options={models.map((m) => ({
                    value: m.id,
                    label: `${m.name}${m.isLoaded ? "（已加载）" : ""}`,
                  }))}
                  placeholder="选择待评估模型"
                />
              </Col>
              <Col xs={24} lg={8}>
                <Typography.Text type="secondary">提示模板</Typography.Text>
                <Select
                  style={{ width: "100%", marginTop: 8 }}
                  value={selectedPromptId}
                  onChange={setSelectedPromptId}
                  options={prompts.map((p) => ({ value: p.id, label: p.name }))}
                  placeholder="选择提示模板"
                />
              </Col>
              <Col xs={24} lg={8}>
                <Typography.Text type="secondary">
                  参与评估的原始合约
                </Typography.Text>
                <Select
                  mode="multiple"
                  style={{ width: "100%", marginTop: 8 }}
                  value={selectedContractIds}
                  onChange={setSelectedContractIds}
                  options={contracts.map((c) => ({
                    value: c.id,
                    label: c.name,
                  }))}
                  placeholder="选择一批原始合约"
                  showSearch
                  optionFilterProp="label"
                />
              </Col>
            </Row>

            <Row gutter={16} style={{ marginTop: 16 }}>
              <Col xs={24} lg={8}>
                <Typography.Text type="secondary">受害模型</Typography.Text>
                <Select
                  mode="multiple"
                  style={{ width: "100%", marginTop: 8 }}
                  value={selectedVictimModels}
                  onChange={setSelectedVictimModels}
                  options={VICTIM_MODEL_OPTIONS}
                  placeholder="选择参与对比的受害模型"
                />
              </Col>
              <Col xs={24} lg={8}>
                <Typography.Text type="secondary">
                  每份合约生成攻击变体数
                </Typography.Text>
                <InputNumber
                  min={1}
                  max={10}
                  value={variantsPerSource}
                  onChange={(v) => setVariantsPerSource(v || 1)}
                  style={{ width: "100%", marginTop: 8 }}
                />
              </Col>
              <Col
                xs={24}
                lg={16}
                style={{ display: "flex", alignItems: "flex-end" }}
              >
                <Button
                  type="primary"
                  onClick={() => void onStart()}
                  loading={loading}
                >
                  启动鲁棒性评估
                </Button>
              </Col>
            </Row>

            <Divider style={{ margin: "16px 0" }} />

            <Typography.Title
              level={5}
              style={{ marginTop: 0, marginBottom: 8 }}
            >
              任务进度
            </Typography.Title>
            {currentJob ? (
              <Space orientation="vertical" size={8} style={{ width: "100%" }}>
                <Typography.Text type="secondary">
                  当前任务：
                  <Typography.Text code>{currentJob.id}</Typography.Text>{" "}
                  <Tag
                    color={
                      currentJob.status === "success"
                        ? "green"
                        : currentJob.status === "failed"
                          ? "red"
                          : "blue"
                    }
                  >
                    {currentJob.status}
                  </Tag>
                </Typography.Text>
                <Progress
                  percent={progressPercent}
                  size="small"
                  status={
                    currentJob.status === "failed"
                      ? "exception"
                      : currentJob.status === "success"
                        ? "success"
                        : "active"
                  }
                />
              </Space>
            ) : (
              <Typography.Text type="secondary">
                暂无鲁棒性评估任务
              </Typography.Text>
            )}

            <Divider style={{ margin: "16px 0" }} />

            <Typography.Title
              level={5}
              style={{ marginTop: 0, marginBottom: 8 }}
            >
              受害模型对比
            </Typography.Title>
            {metrics ? (
              <Table
                rowKey="victimModel"
                size="small"
                columns={victimColumns}
                dataSource={metrics.victimResults ?? []}
                pagination={false}
                locale={{
                  emptyText: (
                    <Empty
                      image={Empty.PRESENTED_IMAGE_SIMPLE}
                      description="本次评估暂无受害模型结果。"
                    />
                  ),
                }}
              />
            ) : (
              <Typography.Text type="secondary">
                任务完成后将展示鲁棒性指标。
              </Typography.Text>
            )}

            {activeVictim?.visibilityWarning ? (
              <Card
                size="small"
                style={{ marginTop: 12, borderRadius: 12, background: "#fff7e6", borderColor: "#ffd591" }}
              >
                <Typography.Text style={{ color: "#ad6800" }}>
                  {activeVictim.visibilityWarning}
                </Typography.Text>
              </Card>
            ) : null}

            {metrics ? (
              <>
                <Divider style={{ margin: "16px 0" }} />
                <Typography.Title
                  level={5}
                  style={{ marginTop: 0, marginBottom: 8 }}
                >
                  {(activeVictim?.displayName ?? "当前模型")} 指标详情
                </Typography.Title>
                {activeVictim ? (
                  <Space orientation="vertical" size={10} style={{ width: "100%" }}>
                    <Row gutter={[12, 12]}>
                      <Col xs={12} lg={6}>
                        <Card size="small" style={{ borderRadius: 12 }}>
                          <Statistic title="攻击成功率" value={attackSuccessRateText} />
                        </Card>
                      </Col>
                      <Col xs={12} lg={6}>
                        <Card size="small" style={{ borderRadius: 12 }}>
                          <Statistic title="准确率下降" value={accuracyDropRateText} />
                        </Card>
                      </Col>
                      <Col xs={12} lg={6}>
                        <Card size="small" style={{ borderRadius: 12 }}>
                          <Statistic title="平均查询次数" value={avgQueriesText} />
                        </Card>
                      </Col>
                      <Col xs={12} lg={6}>
                        <Card size="small" style={{ borderRadius: 12 }}>
                          <Statistic title="平均 CodeBLEU" value={avgCodeBLEUText} />
                        </Card>
                      </Col>
                    </Row>
                    <Card
                      size="small"
                      style={{ borderRadius: 14, background: "#fafafa" }}
                      styles={{ body: { padding: 16 } }}
                    >
                      <Row gutter={[16, 16]}>
                        <Col xs={24} lg={8}>
                          <Space orientation="vertical" size={6} style={{ width: "100%" }}>
                            <Typography.Text type="secondary">实验范围</Typography.Text>
                            <div>
                              <Typography.Text strong>攻击目标漏洞：</Typography.Text>
                              <Typography.Text>{activeVictim.targetVulnType ?? metrics.targetVulnType ?? "--"}</Typography.Text>
                            </div>
                            <div>
                              <Typography.Text strong>可攻击样本：</Typography.Text>
                              <Typography.Text>{activeVictim.attackableContracts ?? "--"}</Typography.Text>
                            </div>
                            <div>
                              <Typography.Text strong>对抗样本数：</Typography.Text>
                              <Typography.Text>{activeVictim.totalAdversarial ?? "--"}</Typography.Text>
                            </div>
                          </Space>
                        </Col>
                        <Col xs={24} lg={8}>
                          <Space orientation="vertical" size={6} style={{ width: "100%" }}>
                            <Typography.Text type="secondary">攻击效果</Typography.Text>
                            <div>
                              <Typography.Text strong>攻击成功率：</Typography.Text>
                              <Typography.Text>{attackSuccessRateText}</Typography.Text>
                            </div>
                            <div>
                              <Typography.Text strong>准确率下降值：</Typography.Text>
                              <Typography.Text>{accuracyDropRateText}</Typography.Text>
                            </div>
                            <div>
                              <Typography.Text strong>平均置信度下降：</Typography.Text>
                              <Typography.Text>{avgDropText}</Typography.Text>
                            </div>
                          </Space>
                        </Col>
                        <Col xs={24} lg={8}>
                          <Space orientation="vertical" size={6} style={{ width: "100%" }}>
                            <Typography.Text type="secondary">攻击成本与质量</Typography.Text>
                            <div>
                              <Typography.Text strong>平均查询次数：</Typography.Text>
                              <Typography.Text>{avgQueriesText}</Typography.Text>
                            </div>
                            <div>
                              <Typography.Text strong>总扰动率：</Typography.Text>
                              <Typography.Text>{avgPerturbationRateText}</Typography.Text>
                            </div>
                            <div>
                              <Typography.Text strong>可见扰动率：</Typography.Text>
                              <Typography.Text>{avgVisiblePerturbationRateText}</Typography.Text>
                            </div>
                            <div>
                              <Typography.Text strong>平均 CodeBLEU：</Typography.Text>
                              <Typography.Text>{avgCodeBLEUText}</Typography.Text>
                            </div>
                            <div>
                              <Typography.Text strong>查询上限命中数：</Typography.Text>
                              <Typography.Text>{queryBudgetHitsText}</Typography.Text>
                            </div>
                          </Space>
                        </Col>
                      </Row>
                    </Card>
                    {!activeVictim.supported ? (
                      <Typography.Text type="secondary">
                        {activeVictim.skippedReason ?? "当前漏洞类型暂未接入该受害模型。"}
                      </Typography.Text>
                    ) : null}
                  </Space>
                ) : (
                  <Typography.Text type="secondary">
                    请先从上方受害模型对比表中选择一个模型查看详情。
                  </Typography.Text>
                )}

                <Typography.Title
                  level={5}
                  style={{ marginTop: 0, marginBottom: 8 }}
                    >
                  原始样本与 DIP 攻击明细
                </Typography.Title>
                <Table
                  rowKey="baseContractId"
                  size="small"
                  columns={contractColumns}
                  dataSource={perContractRows}
                  locale={{
                    emptyText: (
                      <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="本次评估暂无可展示的攻击明细。"
                      />
                    ),
                  }}
                  pagination={{ pageSize: 6, hideOnSinglePage: true }}
                />

                <Divider style={{ margin: "16px 0" }} />
                {(showQueryChart || showCodebleuChart) ? (
                <Row gutter={[16, 16]}>
                  {showQueryChart ? (
                  <Col xs={24} lg={12}>
                    <Typography.Title
                      level={5}
                      style={{ marginTop: 0, marginBottom: 8 }}
                    >
                      多模型查询成本对比
                    </Typography.Title>
                    <Card
                      size="small"
                      style={{ borderRadius: 12, background: "#fafafa" }}
                    >
                      <Column
                          data={queryComparisonData}
                          xField="victim"
                          yField="value"
                          height={220}
                          label={{
                            position: "top",
                            content: (d: any) => formatFixed(d.value, 2),
                          }}
                          xAxis={{ label: { autoHide: true, autoRotate: false } }}
                          yAxis={{ title: { text: "平均查询次数" } }}
                          tooltip={{
                            formatter: (d: any) => ({
                              name: d.victim,
                              value: `平均查询次数 ${formatFixed(d.value, 2)}`,
                            }),
                          }}
                        />
                    </Card>
                  </Col>
                  ) : null}
                  {showCodebleuChart ? (
                  <Col xs={24} lg={12}>
                    <Typography.Title
                      level={5}
                      style={{ marginTop: 0, marginBottom: 8 }}
                    >
                      多模型代码相似度对比
                    </Typography.Title>
                    <Card
                      size="small"
                      style={{ borderRadius: 12, background: "#fafafa" }}
                    >
                      <Column
                          data={codebleuComparisonData}
                          xField="victim"
                          yField="value"
                          height={220}
                          label={{
                            position: "top",
                            content: (d: any) => formatFixed(d.value, 4),
                          }}
                          xAxis={{ label: { autoHide: true, autoRotate: false } }}
                          yAxis={{ title: { text: "平均 CodeBLEU" } }}
                          tooltip={{
                            formatter: (d: any) => ({
                              name: d.victim,
                              value: `平均 CodeBLEU ${formatFixed(d.value, 4)}`,
                            }),
                          }}
                        />
                    </Card>
                  </Col>
                  ) : null}
                </Row>
                ) : (
                  <Card size="small" style={{ borderRadius: 12, background: "#fafafa" }}>
                    <Typography.Text type="secondary">
                      本轮评估中攻击结论指标大多接近 0，图表信息量不足，因此这里只保留对比表和样本明细。
                    </Typography.Text>
                  </Card>
                )}
              </>
            ) : null}
          </>
        ) : (
          <Space orientation="vertical" size={12} style={{ width: "100%" }}>
            <Row justify="space-between" align="middle">
              <Col>
                <Typography.Text type="secondary">
                  点击“查看”可回溯任意一次鲁棒性评估结果。
                </Typography.Text>
              </Col>
              <Col>
                <Button onClick={() => void refreshHistory()}>刷新列表</Button>
              </Col>
            </Row>
            <Table
              rowKey="id"
              size="small"
              columns={historyColumns}
              dataSource={historyJobs}
              pagination={{ pageSize: 8, hideOnSinglePage: true }}
            />
          </Space>
        )}
      </Card>
    </Space>
  );
}
