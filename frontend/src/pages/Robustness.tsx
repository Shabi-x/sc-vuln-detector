import { useEffect, useMemo, useState } from "react";
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
  Table,
  Tag,
  Tabs,
  Typography,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { Pie, Column } from "@ant-design/plots";
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

const STRATEGY_OPTIONS = [
  { label: "标识符改名", value: "rename-identifiers" },
  { label: "插入死代码", value: "insert-dead-code" },
  { label: "触发词注入", value: "trigger-injection" },
];

export default function Robustness() {
  const [activeTab, setActiveTab] = useState<"run" | "history">("run");
  const [contracts, setContracts] = useState<ContractSummary[]>([]);
  const [prompts, setPrompts] = useState<Prompt[]>([]);
  const [models, setModels] = useState<TrainedModel[]>([]);
  const [historyJobs, setHistoryJobs] = useState<RobustJob[]>([]);

  const [selectedContractIds, setSelectedContractIds] = useState<string[]>([]);
  const [selectedPromptId, setSelectedPromptId] = useState<string>();
  const [selectedModelId, setSelectedModelId] = useState<string>();
  const [strategies, setStrategies] = useState<string[]>([
    "rename-identifiers",
  ]);
  const [variantsPerSource, setVariantsPerSource] = useState(1);

  const [loading, setLoading] = useState(false);
  const [currentJob, setCurrentJob] = useState<RobustJob | null>(null);
  const [metrics, setMetrics] = useState<RobustMetrics | null>(null);

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
        if (cs.length > 0) {
          setSelectedContractIds([cs[0]!.id]);
        }
        if (ps.length > 0) setSelectedPromptId(ps[0]!.id);
        const loaded = ms.find((m) => m.isLoaded);
        if (loaded) setSelectedModelId(loaded.id);
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
    const tick = async () => {
      try {
        const data = await getRobustJob(jobId);
        setCurrentJob(data.job);
        setMetrics(data.metrics ?? null);
        if (data.job.status === "queued" || data.job.status === "running") {
          setTimeout(tick, 1000);
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
    if (strategies.length === 0) {
      message.warning("请至少选择一种扰动策略");
      return;
    }
    try {
      setLoading(true);
      const job = await createRobustJob({
        modelId: selectedModelId,
        promptId: selectedPromptId,
        contractIds: selectedContractIds,
        strategies,
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

  const flipRateText =
    metrics && typeof metrics.flipRate === "number"
      ? `${(metrics.flipRate * 100).toFixed(2)}%`
      : "--";
  const avgDropText =
    metrics && typeof metrics.avgConfidenceDrop === "number"
      ? metrics.avgConfidenceDrop.toFixed(4)
      : "--";

  const pieData = useMemo(() => {
    if (!metrics?.totalAdversarial) return [];
    const flipped = metrics.flipped ?? 0;
    const stable = Math.max(0, metrics.totalAdversarial - flipped);
    return [
      { type: "预测翻转", value: flipped },
      { type: "预测一致", value: stable },
    ];
  }, [metrics]);

  // 用“翻转/一致”的堆叠柱状图呈现，避免 flipRate=0 时柱子高度为 0 看起来像空白
  const strategyChartData = useMemo(() => {
    const arr = metrics?.perStrategy ?? [];
    return arr.flatMap((s) => {
      const total = s.total ?? 0;
      const flipped = s.flipped ?? 0;
      const stable = Math.max(0, total - flipped);
      return [
        {
          strategy: s.strategy,
          kind: "预测一致",
          value: stable,
          flipRate: Math.round((s.flipRate ?? 0) * 10000) / 100,
        },
        {
          strategy: s.strategy,
          kind: "预测翻转",
          value: flipped,
          flipRate: Math.round((s.flipRate ?? 0) * 10000) / 100,
        },
      ];
    });
  }, [metrics]);

  const perContractRows = useMemo(() => metrics?.perContract ?? [], [metrics]);

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
      render: (v: string, r) => (
        <Space size={8}>
          <Typography.Text strong>{v}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {r.baseContractId}
          </Typography.Text>
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
            {r.origConfidence.toFixed(4)}
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
      title: "翻转次数",
      dataIndex: "flipped",
      width: 110,
      render: (v: number) => <Typography.Text>{v}</Typography.Text>,
    },
    {
      title: "对抗平均置信度",
      dataIndex: "avgAdvConfidence",
      width: 150,
      render: (v: number) => <Typography.Text>{v.toFixed(4)}</Typography.Text>,
    },
    {
      title: "平均置信度下降",
      dataIndex: "avgConfDrop",
      width: 150,
      render: (v: number) => <Typography.Text>{v.toFixed(4)}</Typography.Text>,
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
              对抗攻击与鲁棒性
            </Typography.Title>
            <Typography.Text type="secondary">
              围绕同一批合约生成对抗样本，在相同模型与提示配置下比较原始与扰动版本的预测差异，评估模型鲁棒性。
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
              options={contracts.map((c) => ({ value: c.id, label: c.name }))}
              placeholder="选择一批原始合约"
              showSearch
              optionFilterProp="label"
            />
          </Col>
        </Row>

        <Row gutter={16} style={{ marginTop: 16 }}>
          <Col xs={24} lg={10}>
            <Typography.Text type="secondary">扰动策略</Typography.Text>
            <Select
              mode="multiple"
              style={{ width: "100%", marginTop: 8 }}
              value={strategies}
              onChange={setStrategies}
              options={STRATEGY_OPTIONS}
              placeholder="选择一种或多种扰动策略"
            />
          </Col>
          <Col xs={24} lg={6}>
            <Typography.Text type="secondary">
              每份合约生成对抗样本数
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
            lg={8}
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

            <Typography.Title level={5} style={{ marginTop: 0, marginBottom: 8 }}>
          任务进度
            </Typography.Title>
            {currentJob ? (
              <Space direction="vertical" size={8} style={{ width: "100%" }}>
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
              <Typography.Text type="secondary">暂无鲁棒性评估任务</Typography.Text>
            )}

            <Divider style={{ margin: "16px 0" }} />

            <Typography.Title level={5} style={{ marginTop: 0, marginBottom: 8 }}>
          鲁棒性指标
            </Typography.Title>
            {metrics ? (
              <Space direction="vertical" size={6} style={{ width: "100%" }}>
            <Typography.Text>
              对抗样本数：{metrics.totalAdversarial ?? "--"}，翻转次数：
              {metrics.flipped ?? "--"}
            </Typography.Text>
            <Typography.Text>
              预测翻转率（Flip Rate）：
              <Typography.Text strong>{flipRateText}</Typography.Text>
            </Typography.Text>
            <Typography.Text>
              平均置信度下降：
              <Typography.Text strong>{avgDropText}</Typography.Text>
            </Typography.Text>
              </Space>
            ) : (
              <Typography.Text type="secondary">任务完成后将展示鲁棒性指标。</Typography.Text>
            )}

            {metrics ? (
              <>
            <Divider style={{ margin: "16px 0" }} />
            <Row gutter={[16, 16]}>
              <Col xs={24} lg={10}>
                <Typography.Title
                  level={5}
                  style={{ marginTop: 0, marginBottom: 8 }}
                >
                  预测翻转占比
                </Typography.Title>
                <Card
                  size="small"
                  style={{ borderRadius: 12, background: "#fafafa" }}
                >
                  <Pie
                    data={pieData}
                    angleField="value"
                    colorField="type"
                    height={220}
                    innerRadius={0.55}
                    legend={{ position: "bottom" }}
                    label={{
                      type: "spider",
                      content: (d: any) =>
                        `${d.type} ${typeof d.percent === "number" ? (d.percent * 100).toFixed(1) : "--"}%`,
                    }}
                    interactions={[{ type: "element-active" }]}
                  />
                </Card>
              </Col>
              <Col xs={24} lg={14}>
                <Typography.Title
                  level={5}
                  style={{ marginTop: 0, marginBottom: 8 }}
                >
                  按策略翻转情况
                </Typography.Title>
                <Card
                  size="small"
                  style={{ borderRadius: 12, background: "#fafafa" }}
                >
                  {strategyChartData.length ? (
                    <Column
                      data={strategyChartData}
                      xField="strategy"
                      yField="value"
                      seriesField="kind"
                      isStack
                      height={220}
                      xAxis={{ label: { autoHide: true, autoRotate: false } }}
                      yAxis={{
                        min: 0,
                        tickCount: 6,
                        title: { text: "样本数" },
                      }}
                      tooltip={{
                        formatter: (d: any) => ({
                          name: d.kind,
                          value: `${d.value}（翻转率 ${d.flipRate}%）`,
                        }),
                      }}
                    />
                  ) : (
                    <div
                      style={{
                        height: 220,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <Empty
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        description="暂无按策略明细（请重启后端后重新运行任务）"
                      />
                    </div>
                  )}
                </Card>
              </Col>
            </Row>

            <Divider style={{ margin: "16px 0" }} />
            <Typography.Title
              level={5}
              style={{ marginTop: 0, marginBottom: 8 }}
            >
              原始 vs 对抗对比明细
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
                    description="暂无对比明细（请重启后端后重新运行任务）"
                  />
                ),
              }}
              pagination={{ pageSize: 6, hideOnSinglePage: true }}
            />
              </>
            ) : null}
          </>
        ) : (
          <Space direction="vertical" size={12} style={{ width: "100%" }}>
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
