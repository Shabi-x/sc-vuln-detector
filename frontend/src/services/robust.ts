import { http } from './http'

export type RobustJobStatus = 'queued' | 'running' | 'success' | 'failed'

export type RobustJob = {
  id: string
  status: RobustJobStatus
  modelId: string
  promptId: string
  attackConfigJson: string
  metricsJson: string
  error: string
  startedAt?: string | null
  finishedAt?: string | null
  createdAt: string
  updatedAt: string
}

export type RobustMetrics = {
  totalAdversarial?: number
  flipped?: number
  flipRate?: number
  avgConfidenceDrop?: number
  perStrategy?: Array<{
    strategy: string
    total: number
    flipped: number
    flipRate: number
    avgConfidenceDrop: number
  }>
  perContract?: Array<{
    baseContractId: string
    contractName: string
    origLabel: string
    origConfidence: number
    advTotal: number
    flipped: number
    avgAdvConfidence: number
    avgConfDrop: number
    byStrategy?: Record<string, { total: number; flipped: number; avgConfDrop: number }>
  }>
  [key: string]: unknown
}

export async function createRobustJob(body: {
  modelId: string
  promptId: string
  contractIds: string[]
  strategies: string[]
  variantsPerSource: number
}) {
  const { data } = await http.post<RobustJob>('/api/robust/evaluate', body)
  return data
}

export async function getRobustJob(id: string) {
  const { data } = await http.get<{
    job: RobustJob
    metrics?: RobustMetrics
  }>(`/api/robust/jobs/${id}`)
  return data
}

export async function listRobustJobs() {
  const { data } = await http.get<RobustJob[]>('/api/robust/jobs')
  return data
}

