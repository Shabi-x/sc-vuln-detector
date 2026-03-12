import { Layout, Menu, Typography } from 'antd'
import {
  CloudUploadOutlined,
  ExperimentOutlined,
  FileSearchOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from '@ant-design/icons'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import type { MenuProps } from 'antd'

const { Header, Sider, Content } = Layout

const items: MenuProps['items'] = [
  {
    key: '/contracts',
    icon: <CloudUploadOutlined />,
    label: '数据管理',
  },
  {
    key: '/training',
    icon: <ExperimentOutlined />,
    label: '小样本训练',
  },
  {
    key: '/detection',
    icon: <FileSearchOutlined />,
    label: '漏洞检测',
  },
  {
    key: '/robustness',
    icon: <SafetyCertificateOutlined />,
    label: '对抗与鲁棒性',
  },
  {
    key: '/prompts',
    icon: <SettingOutlined />,
    label: '提示模板',
  },
  {
    key: '/report',
    icon: <SettingOutlined />,
    label: '报告导出',
  },
]

export default function MainLayout() {
  const nav = useNavigate()
  const loc = useLocation()

  return (
    <Layout className="app-shell">
      <Sider
        theme="light"
        width={248}
        style={{
          borderRight: '1px solid rgba(5, 5, 5, 0.06)',
          background: '#fff',
        }}
      >
        <div style={{ padding: '16px 16px 8px 16px' }}>
          <Typography.Title level={4} style={{ margin: 0 }}>
            SC Vuln Detector
          </Typography.Title>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            智能合约漏洞检测与鲁棒性评估
          </Typography.Text>
        </div>
        <Menu
          mode="inline"
          items={items}
          selectedKeys={[loc.pathname]}
          onClick={(e) => nav(e.key)}
          style={{ borderInlineEnd: 0 }}
        />
      </Sider>
      <Layout>
        <Header
          style={{
            background: '#fff',
            borderBottom: '1px solid rgba(5, 5, 5, 0.06)',
            padding: '0 20px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div />
          <div />
        </Header>
        <Content style={{ padding: 20 }}>
          <Outlet />
        </Content>
      </Layout>
    </Layout>
  )
}

