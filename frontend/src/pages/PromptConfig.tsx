import { useEffect, useMemo, useState } from 'react'
import {
  Button,
  Card,
  Col,
  Divider,
  Drawer,
  Form,
  Input,
  Popconfirm,
  Radio,
  Row,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  createPrompt,
  createPromptMapping,
  deletePrompt,
  deletePromptMapping,
  listPromptMappings,
  listPrompts,
  updatePrompt,
  updatePromptMapping,
  type Label,
  type Prompt,
  type PromptMapping,
  type PromptType,
} from '../services/prompts'

const LS_SELECTED_PROMPT_ID = 'scvd:selectedPromptId'

const labelText: Record<Label, string> = {
  vulnerable: '有漏洞',
  nonVulnerable: '无漏洞',
}

function promptTypeText(t: PromptType) {
  return t === 'hard' ? '硬提示' : '软提示'
}

function validateHardTemplate(s: string) {
  const okX = s.includes('[X]')
  return okX ? null : '硬提示模板必须包含 [X]'
}

export default function PromptConfig() {
  const [loadingPrompts, setLoadingPrompts] = useState(false)
  const [prompts, setPrompts] = useState<Prompt[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(
    localStorage.getItem(LS_SELECTED_PROMPT_ID),
  )

  const selected = useMemo(
    () => prompts.find((p) => p.id === selectedId) ?? null,
    [prompts, selectedId],
  )

  const [loadingMappings, setLoadingMappings] = useState(false)
  const [mappings, setMappings] = useState<PromptMapping[]>([])

  const [drawerOpen, setDrawerOpen] = useState(false)
  const [editing, setEditing] = useState<Prompt | null>(null)
  const [form] = Form.useForm<{
    name: string
    type: PromptType
    description: string
    templateText: string
    softConfigJson: string
    isActive: boolean
  }>()

  const [mapDrawerOpen, setMapDrawerOpen] = useState(false)
  const [editingMap, setEditingMap] = useState<PromptMapping | null>(null)
  const [mapForm] = Form.useForm<{
    token: string
    label: Label
    isDefault: boolean
  }>()

  const refreshPrompts = async () => {
    setLoadingPrompts(true)
    try {
      const list = await listPrompts()
      setPrompts(list)
      if (!selectedId && list.length > 0) {
        setSelectedId(list[0]!.id)
      }
      if (selectedId && !list.some((p) => p.id === selectedId)) {
        setSelectedId(list[0]?.id ?? null)
      }
    } catch (e) {
      message.error(`加载模板失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setLoadingPrompts(false)
    }
  }

  const refreshMappings = async (promptId: string) => {
    setLoadingMappings(true)
    try {
      const list = await listPromptMappings(promptId)
      setMappings(list)
    } catch (e) {
      message.error(`加载映射失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setLoadingMappings(false)
    }
  }

  useEffect(() => {
    void refreshPrompts()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (selectedId) {
      localStorage.setItem(LS_SELECTED_PROMPT_ID, selectedId)
      void refreshMappings(selectedId)
    } else {
      localStorage.removeItem(LS_SELECTED_PROMPT_ID)
      setMappings([])
    }
  }, [selectedId])

  const openCreateDrawer = (type: PromptType) => {
    setEditing(null)
    form.setFieldsValue({
      name: '',
      type,
      description: '',
      templateText: type === 'hard' ? 'The code [X] is [MASK].' : '',
      softConfigJson: type === 'soft' ? '{"promptLength":16}' : '',
      isActive: true,
    })
    setDrawerOpen(true)
  }

  const openEditDrawer = (p: Prompt) => {
    setEditing(p)
    form.setFieldsValue({
      name: p.name,
      type: p.type,
      description: p.description,
      templateText: p.templateText,
      softConfigJson: p.softConfigJson,
      isActive: p.isActive,
    })
    setDrawerOpen(true)
  }

  const submitPrompt = async () => {
    const v = await form.validateFields()
    if (v.type === 'hard') {
      const msg = validateHardTemplate(v.templateText)
      if (msg) {
        message.error(msg)
        return
      }
    }

    try {
      if (!editing) {
        await createPrompt(v)
        message.success('模板已创建')
      } else {
        await updatePrompt(editing.id, v)
        message.success('模板已更新')
      }
      setDrawerOpen(false)
      await refreshPrompts()
    } catch (e) {
      message.error(`保存失败：${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const removePrompt = async (p: Prompt) => {
    try {
      await deletePrompt(p.id)
      message.success('已删除')
      if (selectedId === p.id) setSelectedId(null)
      await refreshPrompts()
    } catch (e) {
      message.error(`删除失败：${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const openCreateMap = () => {
    if (!selected) return
    setEditingMap(null)
    mapForm.setFieldsValue({ token: '', label: 'vulnerable', isDefault: true })
    setMapDrawerOpen(true)
  }

  const openEditMap = (m: PromptMapping) => {
    setEditingMap(m)
    mapForm.setFieldsValue({
      token: m.token,
      label: m.label,
      isDefault: m.isDefault,
    })
    setMapDrawerOpen(true)
  }

  const submitMap = async () => {
    if (!selected) return
    const v = await mapForm.validateFields()
    try {
      if (!editingMap) {
        await createPromptMapping({ ...v, promptId: selected.id })
        message.success('映射已创建')
      } else {
        await updatePromptMapping(editingMap.id, v)
        message.success('映射已更新')
      }
      setMapDrawerOpen(false)
      await refreshMappings(selected.id)
    } catch (e) {
      message.error(`保存失败：${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const removeMap = async (m: PromptMapping) => {
    if (!selected) return
    try {
      await deletePromptMapping(m.id)
      message.success('已删除')
      await refreshMappings(selected.id)
    } catch (e) {
      message.error(`删除失败：${e instanceof Error ? e.message : String(e)}`)
    }
  }

  const promptColumns: ColumnsType<Prompt> = [
    {
      title: '名称',
      dataIndex: 'name',
      render: (_, p) => (
        <Space size={8}>
          <Typography.Text strong>{p.name}</Typography.Text>
          {p.isPreset ? <Tag color="blue">预设</Tag> : null}
          {!p.isActive ? <Tag>停用</Tag> : null}
        </Space>
      ),
    },
    {
      title: '类型',
      dataIndex: 'type',
      width: 110,
      render: (t: PromptType) => (
        <Tag color={t === 'hard' ? 'geekblue' : 'purple'}>
          {promptTypeText(t)}
        </Tag>
      ),
    },
    {
      title: '描述',
      dataIndex: 'description',
      ellipsis: true,
    },
    {
      title: '操作',
      width: 210,
      render: (_, p) => (
        <Space>
          <Button size="small" onClick={() => setSelectedId(p.id)}>
            选择
          </Button>
          <Button size="small" onClick={() => openEditDrawer(p)}>
            编辑
          </Button>
          <Popconfirm
            title="确认删除该模板？"
            description="会同时删除该模板的标签映射规则。"
            okText="删除"
            okButtonProps={{ danger: true }}
            cancelText="取消"
            onConfirm={() => void removePrompt(p)}
            disabled={p.isPreset}
          >
            <Button size="small" danger disabled={p.isPreset}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const mappingColumns: ColumnsType<PromptMapping> = [
    {
      title: '标签词（token）',
      dataIndex: 'token',
      width: 180,
      render: (t: string) => <Typography.Text code>{t}</Typography.Text>,
    },
    {
      title: '类别',
      dataIndex: 'label',
      width: 160,
      render: (l: Label) => (
        <Tag color={l === 'vulnerable' ? 'red' : 'green'}>{labelText[l]}</Tag>
      ),
    },
    {
      title: '默认',
      dataIndex: 'isDefault',
      width: 100,
      render: (v: boolean) => (v ? <Tag color="blue">是</Tag> : <Tag>否</Tag>),
    },
    {
      title: '操作',
      width: 180,
      render: (_, m) => (
        <Space>
          <Button size="small" onClick={() => openEditMap(m)}>
            编辑
          </Button>
          <Popconfirm
            title="确认删除该映射？"
            okText="删除"
            okButtonProps={{ danger: true }}
            cancelText="取消"
            onConfirm={() => void removeMap(m)}
          >
            <Button size="small" danger>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const selectedSummary = selected ? (
    <Space size={8} wrap>
      <Tag color="blue">当前生效</Tag>
      <Typography.Text strong>{selected.name}</Typography.Text>
      <Tag color={selected.type === 'hard' ? 'geekblue' : 'purple'}>
        {promptTypeText(selected.type)}
      </Tag>
      {selected.isActive ? null : <Tag>停用</Tag>}
    </Space>
  ) : (
    <Typography.Text type="secondary">请选择一个模板</Typography.Text>
  )

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card bordered={false} style={{ borderRadius: 12 }} styles={{ body: { padding: 20 } }}>
        <Row gutter={[16, 12]} align="middle">
          <Col flex="auto">
            <Typography.Title level={3} style={{ marginTop: 0, marginBottom: 4 }}>
              提示模板配置
            </Typography.Title>
            <Typography.Text type="secondary">
              管理硬提示/软提示模板与标签词映射（verbalizer）。切换模板后立即生效。
            </Typography.Text>
          </Col>
          <Col>
            <Space>
              <Button onClick={() => void refreshPrompts()} loading={loadingPrompts}>
                刷新
              </Button>
              <Button onClick={() => openCreateDrawer('hard')}>新建硬提示</Button>
              <Button type="primary" onClick={() => openCreateDrawer('soft')}>
                新建软提示
              </Button>
            </Space>
          </Col>
        </Row>
        <div style={{ marginTop: 12 }}>{selectedSummary}</div>

        <Divider style={{ margin: '16px 0' }} />

        <Tabs
          items={[
            {
              key: 'prompts',
              label: '模板管理',
              children: (
                <Space direction="vertical" size={12} style={{ width: '100%' }}>
                  <Table
                    rowKey="id"
                    loading={loadingPrompts}
                    columns={promptColumns}
                    dataSource={prompts}
                    size="middle"
                    pagination={{ pageSize: 8, hideOnSinglePage: true }}
                    rowSelection={{
                      type: 'radio',
                      selectedRowKeys: selectedId ? [selectedId] : [],
                      onChange: (keys) => setSelectedId((keys[0] as string) ?? null),
                    }}
                  />

                  <Card
                    size="small"
                    bordered
                    style={{ borderRadius: 12, background: '#fafafa' }}
                    styles={{ body: { padding: 14 } }}
                  >
                    {selected ? (
                      <Space direction="vertical" size={6} style={{ width: '100%' }}>
                        <Typography.Text type="secondary">
                          当前选择模板预览（训练/检测将引用此配置）
                        </Typography.Text>
                        <Space size={8} wrap>
                          <Typography.Text strong>{selected.name}</Typography.Text>
                          <Tag color={selected.type === 'hard' ? 'geekblue' : 'purple'}>
                            {promptTypeText(selected.type)}
                          </Tag>
                          {selected.isPreset ? <Tag color="blue">预设</Tag> : null}
                          {selected.isActive ? null : <Tag>停用</Tag>}
                        </Space>
                        {selected.type === 'hard' ? (
                          <Typography.Paragraph style={{ marginBottom: 0 }}>
                            <Typography.Text type="secondary">模板：</Typography.Text>
                            <br />
                            <Typography.Text code style={{ whiteSpace: 'pre-wrap' }}>
                              {selected.templateText || '(空)'}
                            </Typography.Text>
                          </Typography.Paragraph>
                        ) : (
                          <Typography.Paragraph style={{ marginBottom: 0 }}>
                            <Typography.Text type="secondary">软提示参数：</Typography.Text>
                            <br />
                            <Typography.Text code style={{ whiteSpace: 'pre-wrap' }}>
                              {selected.softConfigJson || '(空)'}
                            </Typography.Text>
                          </Typography.Paragraph>
                        )}
                      </Space>
                    ) : (
                      <Typography.Text type="secondary">请选择模板后查看预览</Typography.Text>
                    )}
                  </Card>
                </Space>
              ),
            },
            {
              key: 'mappings',
              label: '标签词映射',
              children: (
                <Space direction="vertical" size={12} style={{ width: '100%' }}>
                  <Row gutter={[12, 12]} align="middle">
                    <Col flex="auto">
                      <Space direction="vertical" size={4} style={{ width: '100%' }}>
                        <Typography.Text type="secondary">
                          先选择模板，再配置该模板的标签词映射（bad/good → 有漏洞/无漏洞）
                        </Typography.Text>
                        <Select
                          placeholder="选择模板…"
                          value={selectedId ?? undefined}
                          onChange={(v) => setSelectedId(v)}
                          options={prompts.map((p) => ({
                            value: p.id,
                            label: `${p.name}（${promptTypeText(p.type)}）`,
                          }))}
                          style={{ width: '100%' }}
                          showSearch
                          optionFilterProp="label"
                        />
                      </Space>
                    </Col>
                    <Col>
                      <Button type="primary" onClick={openCreateMap} disabled={!selected}>
                        添加映射
                      </Button>
                    </Col>
                  </Row>

                  <Table
                    rowKey="id"
                    loading={loadingMappings}
                    columns={mappingColumns}
                    dataSource={mappings}
                    size="middle"
                    pagination={{ pageSize: 8, hideOnSinglePage: true }}
                  />
                </Space>
              ),
            },
          ]}
        />
      </Card>

      <Drawer
        title={editing ? '编辑模板' : '新建模板'}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={520}
        destroyOnClose
        extra={
          <Space>
            <Button onClick={() => setDrawerOpen(false)}>取消</Button>
            <Button type="primary" onClick={() => void submitPrompt()}>
              保存
            </Button>
          </Space>
        }
      >
        <Form layout="vertical" form={form} requiredMark="optional">
          <Form.Item label="类型" name="type" rules={[{ required: true }]}>
            <Radio.Group
              options={[
                { label: '硬提示', value: 'hard' },
                { label: '软提示', value: 'soft' },
              ]}
              optionType="button"
              buttonStyle="solid"
              disabled={!!editing}
            />
          </Form.Item>

          <Form.Item label="名称" name="name" rules={[{ required: true, message: '请输入名称' }]}>
            <Input placeholder="例如：Hard Prompt - 基础二分类" />
          </Form.Item>

          <Form.Item label="描述" name="description">
            <Input placeholder="简要说明模板用途…" />
          </Form.Item>

          <Form.Item shouldUpdate noStyle>
            {() => {
              const t = form.getFieldValue('type') as PromptType
              if (t === 'hard') {
                return (
                  <Form.Item
                    label="硬提示模板内容"
                    name="templateText"
                    rules={[
                      { required: true, message: '请输入模板内容' },
                      {
                        validator: async (_, val) => {
                          const msg = validateHardTemplate(String(val ?? ''))
                          if (msg) throw new Error(msg)
                        },
                      },
                    ]}
                    extra="必须包含 [X]（代码插槽），可选包含 [MASK]。"
                  >
                    <Input.TextArea autoSize={{ minRows: 5, maxRows: 10 }} />
                  </Form.Item>
                )
              }
              return (
                <Form.Item
                  label="软提示参数（JSON）"
                  name="softConfigJson"
                  rules={[{ required: true, message: '请输入软提示参数 JSON' }]}
                  extra="建议存你训练脚本真正会用到的参数，例如 promptLength、init、lr 等。"
                >
                  <Input.TextArea autoSize={{ minRows: 6, maxRows: 12 }} />
                </Form.Item>
              )
            }}
          </Form.Item>

          <Form.Item label="启用" name="isActive" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Drawer>

      <Drawer
        title={editingMap ? '编辑映射' : '添加映射'}
        open={mapDrawerOpen}
        onClose={() => setMapDrawerOpen(false)}
        width={460}
        destroyOnClose
        extra={
          <Space>
            <Button onClick={() => setMapDrawerOpen(false)}>取消</Button>
            <Button type="primary" onClick={() => void submitMap()} disabled={!selected}>
              保存
            </Button>
          </Space>
        }
      >
        {selected ? (
          <Space direction="vertical" size={10} style={{ width: '100%' }}>
            <Typography.Text type="secondary">
              当前模板：<Typography.Text strong>{selected.name}</Typography.Text>
            </Typography.Text>
            <Form layout="vertical" form={mapForm} requiredMark="optional">
              <Form.Item
                label="标签词（token）"
                name="token"
                rules={[{ required: true, message: '请输入标签词，如 bad/good' }]}
              >
                <Input placeholder="bad / good / vulnerable / safe ..." />
              </Form.Item>
              <Form.Item label="对应类别" name="label" rules={[{ required: true }]}>
                <Select
                  options={[
                    { label: '有漏洞', value: 'vulnerable' },
                    { label: '无漏洞', value: 'nonVulnerable' },
                  ]}
                />
              </Form.Item>
              <Form.Item label="默认映射" name="isDefault" valuePropName="checked">
                <Switch />
              </Form.Item>
            </Form>
          </Space>
        ) : (
          <Typography.Text type="secondary">请先选择一个模板</Typography.Text>
        )}
      </Drawer>
    </Space>
  )
}

