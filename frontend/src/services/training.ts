import { http } from './http'

export type TrainJobStatus =
  | 'queued'
  | 'running'
  | 'success'
  | 'failed'
  | 'canceled'

export type TargetVulnType = 'reentrancy' | 'access_control' | 'arithmetic'

export const TARGET_VULN_OPTIONS: Array<{
  label: string
  value: TargetVulnType
}> = [
  { label: '重入漏洞', value: 'reentrancy' },
  { label: '访问控制漏洞', value: 'access_control' },
  { label: '整数算术漏洞', value: 'arithmetic' },
]

export type TrainJob = {
  id: string
  promptId: string
  status: TrainJobStatus
  fewshotSize: number
  paramsJson: string
  datasetRef: string
  error: string
  startedAt?: string | null
  finishedAt?: string | null
  createdAt: string
  updatedAt: string
}

export type TrainMetric = {
  id: string
  jobId: string
  step: number
  epoch: number
  loss: number
  acc: number
  f1: number
  createdAt: string
}

export type TrainedModel = {
  id: string
  trainJobId: string
  name: string
  baseModel: string
  promptId: string
  artifact: string
  metricsJson: string
  isLoaded: boolean
  targetVulnType?: TargetVulnType | ''
  createdAt: string
  updatedAt: string
}

export async function createTrainJob(body: {
  promptId: string
  fewshotSize: number
  datasetRef?: string
  params?: Record<string, unknown>
}) {
  const { data } = await http.post<TrainJob>('/api/train/jobs', body)
  return data
}

export async function getTrainJob(id: string) {
  const { data } = await http.get<TrainJob>(`/api/train/jobs/${id}`)
  return data
}

export async function getTrainJobMetrics(id: string, limit = 200) {
  const { data } = await http.get<TrainMetric[]>(`/api/train/jobs/${id}/metrics`, {
    params: { limit },
  })
  return data
}

export async function listModels() {
  const { data } = await http.get<TrainedModel[]>('/api/models')
  return data
}

export async function loadModel(id: string) {
  const { data } = await http.post<{ ok: boolean; loadedId: string }>(`/api/models/${id}/load`)
  return data
}
