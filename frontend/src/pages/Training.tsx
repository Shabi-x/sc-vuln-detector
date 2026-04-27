import { useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Card,
  Col,
  Descriptions,
  Divider,
  Empty,
  Form,
  Input,
  InputNumber,
  Progress,
  Row,
  Select,
  Space,
  Statistic,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import { Line } from "@ant-design/plots";
import {
  createTrainJob,
  getTrainJob,
  getTrainJobMetrics,
  listModels,
  TARGET_VULN_OPTIONS,
  type TargetVulnType,
  type TrainJob,
  type TrainJobStatus,
  type TrainMetric,
  type TrainedModel,
} from "../services/training";
import { listPrompts, type Prompt } from "../services/prompts";
import { getPageCache, setPageCache } from "../utils/pageCache";

const FEWSHOT_MAX = 64;
const TRAINING_CACHE_KEY = "page:training";

const statusColor: Record<TrainJobStatus, string> = {
  queued: "default",
  running: "processing",
  success: "success",
  failed: "error",
  canceled: "default",
};

function statusText(s: TrainJobStatus) {
  switch (s) {
    case "queued":
      return "排队中";
    case "running":
      return "训练中";
    case "success":
      return "已完成";
    case "failed":
      return "失败";
    case "canceled":
      return "已取消";
    default:
      return s;
  }
}

function vulnTypeText(v: string | undefined) {
  switch (v) {
    case "reentrancy":
      return "重入漏洞";
    case "access_control":
      return "访问控制漏洞";
    case "arithmetic":
      return "整数算术漏洞";
    default:
      return v || "--";
  }
}

function inferModelTarget(name: string) {
  if (name.includes("-reentrancy-")) return "reentrancy";
  if (name.includes("-access-control-")) return "access_control";
  if (name.includes("-arithmetic-")) return "arithmetic";
  return "";
}

export default function Training() {
  const cachedState = getPageCache<{
    formValues?: Partial<{
      promptId: string;
      targetVulnType: TargetVulnType;
      fewshotSize: number;
      epochs: number;
      batchSize: number;
      learningRate: number;
      datasetRef: string;
      baseModel: string;
      maxLength: number;
      seed: number;
    }>;
    currentJob?: TrainJob | null;
    metrics?: TrainMetric[];
  }>(TRAINING_CACHE_KEY);

  const [form] = Form.useForm<{
    promptId: string;
    targetVulnType: TargetVulnType;
    fewshotSize: number;
    epochs: number;
    batchSize: number;
    learningRate: number;
    datasetRef: string;
    baseModel: string;
    maxLength: number;
    seed: number;
  }>();

  const [prompts, setPrompts] = useState<Prompt[]>([]);
  const [loadingPrompts, setLoadingPrompts] = useState(false);

  const [currentJob, setCurrentJob] = useState<TrainJob | null>(
    cachedState?.currentJob ?? null,
  );
  const [metrics, setMetrics] = useState<TrainMetric[]>(
    cachedState?.metrics ?? [],
  );
  const [models, setModels] = useState<TrainedModel[]>([]);

  const [creating, setCreating] = useState(false);
  const pollTimerRef = useRef<number | null>(null);

  const loadedModel = useMemo(
    () => models.find((m) => m.isLoaded) ?? null,
    [models],
  );

  const latestMetric = metrics.length ? metrics[metrics.length - 1] : null;

  const metricsForChart = useMemo(
    () =>
      metrics.flatMap((m) => [
        { epoch: m.epoch, value: m.loss, type: "Loss" },
        { epoch: m.epoch, value: m.acc, type: "Acc" },
        { epoch: m.epoch, value: m.f1, type: "F1" },
      ]),
    [metrics],
  );

  useEffect(() => {
    const loadPrompts = async () => {
      setLoadingPrompts(true);
      try {
        const data = await listPrompts({ active: true });
        setPrompts(data);
        if (data.length > 0 && !form.getFieldValue("promptId")) {
          form.setFieldsValue({ promptId: data[0]!.id });
        }
      } catch (e) {
        message.error(
          `加载模板失败：${e instanceof Error ? e.message : String(e)}`,
        );
      } finally {
        setLoadingPrompts(false);
      }
    };
    void loadPrompts();
    void refreshModels();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const initialValues = {
      targetVulnType: "reentrancy" as TargetVulnType,
      fewshotSize: 32,
      epochs: 3,
      batchSize: 4,
      learningRate: 2e-5,
      datasetRef: "smartbugs-curated",
      baseModel: "microsoft/codebert-base",
      maxLength: 256,
      seed: 42,
      ...cachedState?.formValues,
    };
    form.setFieldsValue(initialValues);
  }, [form, cachedState?.formValues]);

  useEffect(() => {
    setPageCache(TRAINING_CACHE_KEY, {
      formValues: form.getFieldsValue(),
      currentJob,
      metrics,
    });
  }, [form, currentJob, metrics]);

  useEffect(() => {
    if (!currentJob || (currentJob.status !== "running" && currentJob.status !== "queued")) {
      return;
    }
    startPolling(currentJob.id);
    return () => {
      if (pollTimerRef.current !== null) {
        window.clearTimeout(pollTimerRef.current);
        pollTimerRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentJob?.id]);

  const refreshModels = async () => {
    try {
      const data = await listModels();
      setModels(data);
    } catch (e) {
      message.error(
        `加载模型列表失败：${e instanceof Error ? e.message : String(e)}`,
      );
    }
  };

  const startPolling = (jobId: string) => {
    if (pollTimerRef.current !== null) {
      window.clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    const tick = async () => {
      try {
        const job = await getTrainJob(jobId);
        setCurrentJob(job);
        const m = await getTrainJobMetrics(jobId, 200);
        setMetrics(m);
        if (job.status === "running" || job.status === "queued") {
          pollTimerRef.current = window.setTimeout(tick, 1000);
        } else {
          void refreshModels();
        }
      } catch (e) {
        message.error(
          `获取训练进度失败：${e instanceof Error ? e.message : String(e)}`,
        );
      }
    };
    void tick();
  };

  const onCreateJob = async () => {
    try {
      const v = await form.validateFields();
      if (v.fewshotSize > FEWSHOT_MAX) {
        message.warning(
          `小样本训练集大小建议不超过 ${FEWSHOT_MAX}，已自动截断`,
        );
        v.fewshotSize = FEWSHOT_MAX;
      }
      setCreating(true);
      const job = await createTrainJob({
        promptId: v.promptId,
        fewshotSize: v.fewshotSize,
        datasetRef: v.datasetRef,
        params: {
          targetVulnType: v.targetVulnType,
          epochs: v.epochs,
          batchSize: v.batchSize,
          learningRate: v.learningRate,
          baseModel: v.baseModel,
          maxLength: v.maxLength,
          seed: v.seed,
        },
      });
      setCurrentJob(job);
      setMetrics([]);
      message.success("训练任务已创建");
      startPolling(job.id);
    } catch (e) {
      if (e instanceof Error) {
        message.error(`创建训练任务失败：${e.message}`);
      }
    } finally {
      setCreating(false);
    }
  };

  const metricsColumns: ColumnsType<TrainMetric> = [
    { title: "Step", dataIndex: "step", width: 80 },
    {
      title: "Loss",
      dataIndex: "loss",
      render: (v: number) => v.toFixed(4),
    },
    {
      title: "Acc",
      dataIndex: "acc",
      render: (v: number) => v.toFixed(4),
    },
    {
      title: "F1",
      dataIndex: "f1",
      render: (v: number) => v.toFixed(4),
    },
  ];

  const modelColumns: ColumnsType<TrainedModel> = [
    {
      title: "名称",
      dataIndex: "name",
      render: (_, m) => (
        <Space size={8}>
          <Typography.Text>{m.name}</Typography.Text>
          {m.isLoaded ? <Tag color="green">当前加载</Tag> : null}
        </Space>
      ),
    },
    { title: "基座模型", dataIndex: "baseModel", width: 120 },
    {
      title: "目标漏洞",
      width: 140,
      render: (_, m) => vulnTypeText(m.targetVulnType || inferModelTarget(m.name)),
    },
    { title: "训练任务", dataIndex: "trainJobId", width: 220 },
  ];

  // 从当前任务的参数中解析出 epochs，便于进度条与图表解释
  const parsedParams = useMemo(() => {
    if (!currentJob?.paramsJson) return {};
    try {
      return JSON.parse(currentJob.paramsJson) as {
        targetVulnType?: TargetVulnType;
        epochs?: number;
        batchSize?: number;
        learningRate?: number;
      };
    } catch {
      return {};
    }
  }, [currentJob]);
  const totalEpochs =
    parsedParams.epochs ??
    (metrics.length ? metrics[metrics.length - 1]!.epoch : 0);
  const currentEpoch = latestMetric?.epoch ?? 0;
  const progressPercent =
    totalEpochs && currentEpoch
      ? Math.min(100, Math.round((currentEpoch / totalEpochs) * 100))
      : 0;

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Card
        bordered={false}
        style={{ borderRadius: 12 }}
        styles={{ body: { padding: 20 } }}
      >
        {/* 顶部标题 */}
        <Row gutter={[16, 12]} align="middle">
          <Col flex="auto">
            <Typography.Title
              level={3}
              style={{ marginTop: 0, marginBottom: 4 }}
            >
              小样本训练
            </Typography.Title>
            <Typography.Text type="secondary">
              按目标漏洞类型构造“存在该漏洞 / 不存在该漏洞”的二分类任务，
              在每类样本数受限的前提下完成小样本提示训练。
            </Typography.Text>
          </Col>
        </Row>

        <Divider style={{ margin: "16px 0" }} />

        {/* 训练配置 */}
        <Row
          justify="space-between"
          align="middle"
          style={{ marginBottom: 12 }}
        >
          <Col>
            <Typography.Title
              level={5}
              style={{ marginTop: 0, marginBottom: 0 }}
            >
              训练配置
            </Typography.Title>
          </Col>
          <Col>
            <Button
              type="primary"
              loading={creating}
              onClick={() => void onCreateJob()}
            >
              启动训练
            </Button>
          </Col>
        </Row>

        <Form
          layout="vertical"
          form={form}
          requiredMark="optional"
          onValuesChange={() => {
            setPageCache(TRAINING_CACHE_KEY, {
              formValues: form.getFieldsValue(),
              currentJob,
              metrics,
            });
          }}
        >
          <Row gutter={16}>
            <Col xs={24} lg={8}>
              <Form.Item
                label="目标漏洞类型"
                name="targetVulnType"
                tooltip="系统会按所选漏洞类型构造 one-vs-rest 二分类训练集。"
                rules={[{ required: true, message: "请选择目标漏洞类型" }]}
              >
                <Select options={TARGET_VULN_OPTIONS} />
              </Form.Item>
            </Col>
            <Col xs={24} lg={8}>
              <Form.Item
                label="提示模板"
                name="promptId"
                rules={[{ required: true, message: "请选择提示模板" }]}
              >
                <Select
                  loading={loadingPrompts}
                  placeholder="请选择一个已启用的提示模板"
                  options={prompts.map((p) => ({
                    value: p.id,
                    label: `${p.name}（${p.type === "hard" ? "硬提示" : "软提示"}）`,
                  }))}
                  showSearch
                  optionFilterProp="label"
                />
              </Form.Item>
            </Col>
            <Col xs={24} lg={8}>
              <Form.Item
                label="每类小样本数量"
                name="fewshotSize"
                tooltip="正类为目标漏洞样本，负类为非目标漏洞样本；每类训练样本数建议不超过 64。"
                rules={[{ required: true, message: "请输入样本数量" }]}
              >
                <InputNumber
                  min={1}
                  max={FEWSHOT_MAX}
                  style={{ width: "100%" }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} lg={6}>
              <Form.Item
                label="Epochs"
                name="epochs"
                rules={[{ required: true, message: "请输入 epochs" }]}
              >
                <InputNumber min={1} max={100} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} lg={6}>
              <Form.Item
                label="Batch Size"
                name="batchSize"
                rules={[{ required: true, message: "请输入 batch size" }]}
              >
                <InputNumber min={1} max={128} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
            <Col xs={24} lg={6}>
              <Form.Item
                label="学习率"
                name="learningRate"
                rules={[{ required: true, message: "请输入学习率" }]}
              >
                <InputNumber
                  min={1e-6}
                  max={1e-2}
                  step={1e-5}
                  style={{ width: "100%" }}
                />
              </Form.Item>
            </Col>
          </Row>
          <Row gutter={16}>
            <Col xs={24} lg={12}>
              <Form.Item
                label="数据集标识"
                name="datasetRef"
                tooltip="支持内置别名或本地绝对路径。默认 smartbugs-curated 会从所选漏洞类型抽取正类，并将其余漏洞样本视为负类。"
              >
                <Input placeholder="例如：smartbugs-curated" />
              </Form.Item>
            </Col>
            <Col xs={24} lg={4}>
              <Form.Item
                label="基座模型"
                name="baseModel"
                tooltip="当前已验证 microsoft/codebert-base。"
              >
                <Input placeholder="例如：microsoft/codebert-base" />
              </Form.Item>
            </Col>
            <Col xs={24} lg={4}>
              <Form.Item
                label="最大长度"
                name="maxLength"
                rules={[{ required: true, message: "请输入最大长度" }]}
              >
                <InputNumber
                  min={64}
                  max={512}
                  step={32}
                  style={{ width: "100%" }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} lg={4}>
              <Form.Item
                label="随机种子"
                name="seed"
                rules={[{ required: true, message: "请输入随机种子" }]}
              >
                <InputNumber min={1} max={999999} style={{ width: "100%" }} />
              </Form.Item>
            </Col>
          </Row>
        </Form>

        <Divider style={{ margin: "16px 0" }} />

        {/* 训练过程可视化：左图右摘要 */}
        <Row gutter={[16, 16]}>
          <Col xs={24} lg={16}>
            <Typography.Title
              level={5}
              style={{ marginTop: 0, marginBottom: 8 }}
            >
              训练曲线
            </Typography.Title>
            {metrics.length ? (
              <Line
                data={metricsForChart}
                height={260}
                xField="epoch"
                yField="value"
                colorField="type"
                smooth
                animation={false}
                xAxis={{ title: { text: "Epoch" }, tickCount: 6 }}
                yAxis={{
                  title: { text: "指标值" },
                  min: 0,
                  max: 1,
                  tickCount: 6,
                }}
                legend={{ position: "top" }}
                tooltip={{ showMarkers: true }}
                scale={{ color: { range: ["#fa8c16", "#52c41a", "#1890ff"] } }}
              />
            ) : (
              <div
                style={{
                  height: 260,
                  borderRadius: 8,
                  background: "#fafafa",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <Empty
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                  description="暂无训练数据"
                />
              </div>
            )}
          </Col>
          <Col xs={24} lg={8}>
            <Typography.Title
              level={5}
              style={{ marginTop: 0, marginBottom: 8 }}
            >
              当前训练任务
            </Typography.Title>
            {currentJob ? (
              <>
                <Descriptions
                  size="small"
                  bordered
                  column={1}
                  style={{ marginBottom: 12 }}
                  labelStyle={{ width: 110 }}
                >
                  <Descriptions.Item label="任务 ID">
                    <Typography.Text code>{currentJob.id}</Typography.Text>
                  </Descriptions.Item>
                  <Descriptions.Item label="状态">
                    <Tag color={statusColor[currentJob.status]}>
                      {statusText(currentJob.status)}
                    </Tag>
                  </Descriptions.Item>
                  <Descriptions.Item label="目标漏洞">
                    {vulnTypeText(parsedParams.targetVulnType)}
                  </Descriptions.Item>
                  <Descriptions.Item label="每类样本数">
                    {currentJob.fewshotSize}
                  </Descriptions.Item>
                  <Descriptions.Item label="错误信息">
                    {currentJob.error || "--"}
                  </Descriptions.Item>
                </Descriptions>
                <Typography.Text type="secondary">
                  训练进度（Epoch {currentEpoch}/{totalEpochs || "-"}）
                </Typography.Text>
                <Progress
                  percent={progressPercent}
                  size="small"
                  status={
                    currentJob.status === "failed" ? "exception" : "active"
                  }
                  style={{ marginBottom: 12 }}
                />
                <Row gutter={12}>
                  <Col span={8}>
                    <Statistic
                      title="最新 Loss"
                      value={latestMetric?.loss ?? 0}
                      precision={4}
                      valueStyle={{ fontSize: 16 }}
                    />
                  </Col>
                  <Col span={8}>
                    <Statistic
                      title="最新 Acc"
                      value={latestMetric?.acc ?? 0}
                      precision={4}
                      valueStyle={{ fontSize: 16 }}
                    />
                  </Col>
                  <Col span={8}>
                    <Statistic
                      title="最新 F1"
                      value={latestMetric?.f1 ?? 0}
                      precision={4}
                      valueStyle={{ fontSize: 16 }}
                    />
                  </Col>
                </Row>
              </>
            ) : (
              <Empty
                image={Empty.PRESENTED_IMAGE_SIMPLE}
                description="暂无训练任务"
              />
            )}
          </Col>
        </Row>

        <Divider style={{ margin: "16px 0" }} />

        {/* 训练明细 + 已训练模型（上下） */}
        <Typography.Title level={5} style={{ marginTop: 0, marginBottom: 8 }}>
          训练明细
        </Typography.Title>
        <Table
          rowKey="id"
          size="small"
          columns={metricsColumns}
          dataSource={metrics}
          pagination={false}
          bordered
          scroll={{ y: 220 }}
        />

        <Typography.Title level={5} style={{ marginTop: 20, marginBottom: 8 }}>
          已训练模型
        </Typography.Title>
        {loadedModel ? (
          <Typography.Paragraph style={{ marginBottom: 8 }}>
            <Typography.Text type="secondary">当前加载模型：</Typography.Text>
            <Typography.Text strong> {loadedModel.name}</Typography.Text>
          </Typography.Paragraph>
        ) : null}
        <Table
          rowKey="id"
          size="small"
          columns={modelColumns}
          dataSource={models}
          pagination={{ pageSize: 5, hideOnSinglePage: true }}
        />
      </Card>
    </Space>
  );
}
