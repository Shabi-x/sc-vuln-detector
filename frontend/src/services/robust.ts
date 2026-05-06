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
  targetVulnType?: string
  attackMethod?: string
  attackPipeline?: string[]
  victimResults?: Array<{
    victimModel: string
    displayName: string
    supported: boolean
    skippedReason?: string
    cacheHit?: boolean
    targetVulnType?: string
    attackableContracts: number
    totalAdversarial: number
    attackSuccesses: number
    attackSuccessRate: number
    origAccuracy: number
    advAccuracy: number
    accuracyDropRate: number
    avgConfidenceDrop: number
    avgQueries: number
    avgPerturbationRate: number
    avgVisiblePerturbationRate: number
    avgCodeBLEU: number
    queryBudgetHits: number
    visibilityWarning?: string
    perStrategy?: Array<{
      strategy: string
      totalVariants: number
      attackSuccesses: number
      attackSuccessRate: number
      avgConfidenceDrop: number
      avgQueries: number
      avgPerturbationRate: number
      avgVisiblePerturbationRate: number
      avgCodeBLEU: number
      queryBudgetHits: number
    }>
    perContract?: Array<{
      baseContractId: string
      contractName: string
      origLabel: string
      origConfidence: number
      origVulnScore: number
      attackable: boolean
      skippedReason?: string
      advTotal: number
      flipped: number
      avgAdvConfidence: number
      avgConfDrop: number
      avgQueries: number
      avgPerturbationRate: number
      avgVisiblePerturbationRate: number
      avgCodeBLEU: number
      queryBudgetHits: number
      bestAttackStrategy?: string
      bestAttackSample?: {
        variantIndex: number
        queries: number
        perturbationTokens: number
        originalTokens: number
        perturbationRate: number
        visiblePerturbationRate: number
        codebleu: number
        queryBudgetHit: boolean
        confidenceDrop: number
        vulnScoreDrop: number
        attackSucceeded: boolean
      }
      byStrategy?: Record<
        string,
        {
          total: number
          attackSuccesses: number
          attackSuccessRate: number
          avgConfidenceDrop: number
          avgQueries: number
          avgPerturbationRate: number
          avgVisiblePerturbationRate: number
          avgCodeBLEU: number
          queryBudgetHits: number
        }
      >
    }>
  }>
  attackableContracts?: number
  totalAdversarial?: number
  attackSuccesses?: number
  attackSuccessRate?: number
  origAccuracy?: number
  advAccuracy?: number
  accuracyDropRate?: number
  avgConfidenceDrop?: number
  avgQueries?: number
  avgPerturbationRate?: number
  avgVisiblePerturbationRate?: number
  avgCodeBLEU?: number
  queryBudgetHits?: number
  inputWindowMaxLength?: number
  visibilityWarning?: string
  perStrategy?: Array<{
    strategy: string
    totalVariants: number
    attackSuccesses: number
    attackSuccessRate: number
    avgConfidenceDrop: number
    avgQueries: number
    avgPerturbationRate: number
    avgVisiblePerturbationRate: number
    avgCodeBLEU: number
    queryBudgetHits: number
  }>
  perContract?: Array<{
    baseContractId: string
    contractName: string
    origLabel: string
    origConfidence: number
    origVulnScore: number
    attackable: boolean
    skippedReason?: string
    advTotal: number
    flipped: number
    avgAdvConfidence: number
    avgConfDrop: number
    avgQueries: number
    avgPerturbationRate: number
    avgVisiblePerturbationRate: number
    avgCodeBLEU: number
    queryBudgetHits: number
    bestAttackStrategy?: string
    bestAttackSample?: {
      variantIndex: number
      queries: number
      perturbationTokens: number
      originalTokens: number
      perturbationRate: number
      visiblePerturbationRate: number
      codebleu: number
      queryBudgetHit: boolean
      confidenceDrop: number
      vulnScoreDrop: number
      attackSucceeded: boolean
    }
    byStrategy?: Record<
      string,
      {
        total: number
        attackSuccesses: number
        attackSuccessRate: number
        avgConfidenceDrop: number
        avgQueries: number
        avgPerturbationRate: number
        avgVisiblePerturbationRate: number
        avgCodeBLEU: number
        queryBudgetHits: number
      }
    >
  }>
  [key: string]: unknown
}

function asNumber(value: unknown, fallback = 0) {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function asString(value: unknown, fallback = '') {
  return typeof value === 'string' ? value : fallback
}

function asBool(value: unknown, fallback = false) {
  return typeof value === 'boolean' ? value : fallback
}

function notNull<T>(value: T | null): value is T {
  return value !== null
}

function normalizeBestAttackSample(sample: any) {
  if (!sample || typeof sample !== 'object') return undefined
  return {
    variantIndex: asNumber(sample.variantIndex),
    queries: asNumber(sample.queries),
    perturbationTokens: asNumber(sample.perturbationTokens),
    originalTokens: asNumber(sample.originalTokens),
    perturbationRate: asNumber(sample.perturbationRate),
    visiblePerturbationRate: asNumber(sample.visiblePerturbationRate),
    codebleu: asNumber(sample.codebleu),
    queryBudgetHit: asBool(sample.queryBudgetHit),
    confidenceDrop: asNumber(sample.confidenceDrop),
    vulnScoreDrop: asNumber(sample.vulnScoreDrop),
    attackSucceeded: asBool(sample.attackSucceeded),
  }
}

function normalizePerStrategy(strategy: any) {
  if (!strategy || typeof strategy !== 'object') return null
  return {
    strategy: asString(strategy.strategy),
    totalVariants: asNumber(strategy.totalVariants ?? strategy.total),
    attackSuccesses: asNumber(strategy.attackSuccesses),
    attackSuccessRate: asNumber(strategy.attackSuccessRate),
    avgConfidenceDrop: asNumber(strategy.avgConfidenceDrop ?? strategy.avgConfDrop),
    avgQueries: asNumber(strategy.avgQueries),
    avgPerturbationRate: asNumber(strategy.avgPerturbationRate),
    avgVisiblePerturbationRate: asNumber(strategy.avgVisiblePerturbationRate),
    avgCodeBLEU: asNumber(strategy.avgCodeBLEU),
    queryBudgetHits: asNumber(strategy.queryBudgetHits),
  }
}

function normalizeByStrategy(byStrategy: unknown) {
  if (!byStrategy || typeof byStrategy !== 'object') return undefined
  return Object.fromEntries(
    Object.entries(byStrategy as Record<string, any>).map(([key, value]) => [
      key,
      {
        total: asNumber(value?.total ?? value?.totalVariants),
        attackSuccesses: asNumber(value?.attackSuccesses),
        attackSuccessRate: asNumber(value?.attackSuccessRate),
        avgConfidenceDrop: asNumber(value?.avgConfidenceDrop ?? value?.avgConfDrop),
        avgQueries: asNumber(value?.avgQueries),
        avgPerturbationRate: asNumber(value?.avgPerturbationRate),
        avgVisiblePerturbationRate: asNumber(value?.avgVisiblePerturbationRate),
        avgCodeBLEU: asNumber(value?.avgCodeBLEU),
        queryBudgetHits: asNumber(value?.queryBudgetHits),
      },
    ]),
  )
}

function normalizePerContract(item: any) {
  if (!item || typeof item !== 'object') return null
  return {
    baseContractId: asString(item.baseContractId),
    contractName: asString(item.contractName),
    origLabel: asString(item.origLabel),
    origConfidence: asNumber(item.origConfidence),
    origVulnScore: asNumber(item.origVulnScore),
    attackable: asBool(item.attackable),
    skippedReason: typeof item.skippedReason === 'string' ? item.skippedReason : undefined,
    advTotal: asNumber(item.advTotal),
    flipped: asNumber(item.flipped),
    avgAdvConfidence: asNumber(item.avgAdvConfidence),
    avgConfDrop: asNumber(item.avgConfDrop ?? item.avgConfidenceDrop),
    avgQueries: asNumber(item.avgQueries),
    avgPerturbationRate: asNumber(item.avgPerturbationRate),
    avgVisiblePerturbationRate: asNumber(item.avgVisiblePerturbationRate),
    avgCodeBLEU: asNumber(item.avgCodeBLEU),
    queryBudgetHits: asNumber(item.queryBudgetHits),
    bestAttackStrategy: item.bestAttackStrategy ? asString(item.bestAttackStrategy) : undefined,
    bestAttackSample: normalizeBestAttackSample(item.bestAttackSample),
    byStrategy: normalizeByStrategy(item.byStrategy),
  }
}

function normalizeVictimResult(item: any) {
  if (!item || typeof item !== 'object') return null
  const perStrategy = Array.isArray(item.perStrategy)
    ? item.perStrategy.map(normalizePerStrategy).filter(notNull)
    : []
  const perContract = Array.isArray(item.perContract)
    ? item.perContract.map(normalizePerContract).filter(notNull)
    : []
  return {
    victimModel: asString(item.victimModel),
    displayName: asString(item.displayName || item.victimModel),
    supported: item.supported !== false,
    skippedReason: item.skippedReason ? asString(item.skippedReason) : undefined,
    cacheHit: typeof item.cacheHit === 'boolean' ? item.cacheHit : undefined,
    targetVulnType: item.targetVulnType ? asString(item.targetVulnType) : undefined,
    attackableContracts: asNumber(item.attackableContracts),
    totalAdversarial: asNumber(item.totalAdversarial),
    attackSuccesses: asNumber(item.attackSuccesses),
    attackSuccessRate: asNumber(item.attackSuccessRate),
    origAccuracy: asNumber(item.origAccuracy),
    advAccuracy: asNumber(item.advAccuracy),
    accuracyDropRate: asNumber(item.accuracyDropRate),
    avgConfidenceDrop: asNumber(item.avgConfidenceDrop),
    avgQueries: asNumber(item.avgQueries),
    avgPerturbationRate: asNumber(item.avgPerturbationRate),
    avgVisiblePerturbationRate: asNumber(item.avgVisiblePerturbationRate),
    avgCodeBLEU: asNumber(item.avgCodeBLEU),
    queryBudgetHits: asNumber(item.queryBudgetHits),
    visibilityWarning: item.visibilityWarning ? asString(item.visibilityWarning) : undefined,
    perStrategy,
    perContract,
  }
}

export function normalizeRobustMetrics(input?: RobustMetrics | Record<string, unknown> | null): RobustMetrics | null {
  if (!input || typeof input !== 'object') return null
  const raw = input as Record<string, unknown>

  const perStrategy = Array.isArray(raw.perStrategy)
    ? raw.perStrategy.map(normalizePerStrategy).filter(notNull)
    : []
  const perContract = Array.isArray(raw.perContract)
    ? raw.perContract.map(normalizePerContract).filter(notNull)
    : []
  const victimResults = Array.isArray(raw.victimResults)
    ? raw.victimResults.map(normalizeVictimResult).filter(notNull)
    : []

  const normalized: RobustMetrics = {
    ...raw,
    targetVulnType: asString(raw.targetVulnType),
    attackMethod: asString(raw.attackMethod),
    attackPipeline: Array.isArray(raw.attackPipeline)
      ? raw.attackPipeline.filter((x): x is string => typeof x === 'string')
      : [],
    attackableContracts: asNumber(raw.attackableContracts),
    totalAdversarial: asNumber(raw.totalAdversarial),
    attackSuccesses: asNumber(raw.attackSuccesses),
    attackSuccessRate: asNumber(raw.attackSuccessRate),
    origAccuracy: asNumber(raw.origAccuracy),
    advAccuracy: asNumber(raw.advAccuracy),
    accuracyDropRate: asNumber(raw.accuracyDropRate),
    avgConfidenceDrop: asNumber(raw.avgConfidenceDrop),
    avgQueries: asNumber(raw.avgQueries),
    avgPerturbationRate: asNumber(raw.avgPerturbationRate),
    avgVisiblePerturbationRate: asNumber(raw.avgVisiblePerturbationRate),
    avgCodeBLEU: asNumber(raw.avgCodeBLEU),
    queryBudgetHits: asNumber(raw.queryBudgetHits),
    inputWindowMaxLength: asNumber(raw.inputWindowMaxLength),
    visibilityWarning: raw.visibilityWarning ? asString(raw.visibilityWarning) : undefined,
    victimResults,
    perStrategy,
    perContract,
  }

  if (victimResults.length === 0) {
    normalized.victimResults = [
      {
        victimModel: 'codebert',
        displayName: 'CodeBERT',
        supported: true,
        targetVulnType: normalized.targetVulnType,
        attackableContracts: normalized.attackableContracts ?? 0,
        totalAdversarial: normalized.totalAdversarial ?? 0,
        attackSuccesses: normalized.attackSuccesses ?? 0,
        attackSuccessRate: normalized.attackSuccessRate ?? 0,
        origAccuracy: normalized.origAccuracy ?? 0,
        advAccuracy: normalized.advAccuracy ?? 0,
        accuracyDropRate: normalized.accuracyDropRate ?? 0,
        avgConfidenceDrop: normalized.avgConfidenceDrop ?? 0,
        avgQueries: normalized.avgQueries ?? 0,
        avgPerturbationRate: normalized.avgPerturbationRate ?? 0,
        avgVisiblePerturbationRate: normalized.avgVisiblePerturbationRate ?? 0,
        avgCodeBLEU: normalized.avgCodeBLEU ?? 0,
        queryBudgetHits: normalized.queryBudgetHits ?? 0,
        visibilityWarning: normalized.visibilityWarning,
        perStrategy,
        perContract,
      },
    ]
  }

  if (!normalized.attackMethod) {
    normalized.attackMethod = perStrategy[0]?.strategy ?? ''
  }
  return normalized
}

export async function createRobustJob(body: {
  modelId: string
  promptId: string
  contractIds: string[]
  victimModels: string[]
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
  return {
    ...data,
    metrics: normalizeRobustMetrics(data.metrics),
  }
}

export async function listRobustJobs() {
  const { data } = await http.get<RobustJob[]>('/api/robust/jobs')
  return data
}
