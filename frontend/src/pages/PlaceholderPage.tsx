import { Card, Typography } from 'antd'

export default function PlaceholderPage(props: {
  title: string
  description?: string
}) {
  return (
    <Card
      styles={{ body: { padding: 24 } }}
      style={{ borderRadius: 12 }}
      bordered={false}
    >
      <Typography.Title level={3} style={{ marginTop: 0 }}>
        {props.title}
      </Typography.Title>
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
        {props.description ?? ''}
      </Typography.Paragraph>
    </Card>
  )
}

