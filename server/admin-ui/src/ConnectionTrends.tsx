import { useId, useState, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, CircleAlert } from 'lucide-react'
import { getLocale, tr } from './i18n'
import { QueryStatus, useAutoRefresh } from './refresh'
import { bucketP95, connectionTrends, lineSegments, summarizeTrends, TREND_WINDOWS, type TrendBucket } from './trends'
import './trends.css'

const CHART_WIDTH = 640
const CHART_HEIGHT = 150
const PLOT_TOP = 10
const PLOT_LEFT = 52

function count(value: number) {
  return new Intl.NumberFormat(getLocale()).format(value)
}

function hourLabel(unix: number, full = false) {
  return new Intl.DateTimeFormat(getLocale(), {
    month: '2-digit', day: '2-digit', hour: '2-digit',
    ...(full ? { minute: '2-digit' as const, timeZoneName: 'short' as const } : {}),
  }).format(unix * 1000)
}

function ChartFrame({ title, legend, max, buckets, selectedIndex, onSelect, children }: {
  title: string
  legend: ReactNode
  max: number
  buckets: TrendBucket[]
  selectedIndex: number
  onSelect: (index: number) => void
  children: ReactNode
}) {
  const titleId = useId()
  return <div className="trend-chart">
    <div className="trend-chart-heading"><h3 id={titleId}>{title}</h3><div className="trend-legend">{legend}</div></div>
    <svg viewBox="0 0 708 192" role="img" aria-labelledby={titleId} onPointerMove={(event) => {
      const bounds = event.currentTarget.getBoundingClientRect()
      const x = (event.clientX - bounds.left) / bounds.width * 708 - PLOT_LEFT
      onSelect(Math.max(0, Math.min(buckets.length - 1, Math.floor(x / CHART_WIDTH * buckets.length))))
    }}>
      <g transform={`translate(${PLOT_LEFT},${PLOT_TOP})`}>
        {[0, 0.5, 1].map((part) => <g key={part}>
          <line x1="0" x2={CHART_WIDTH} y1={CHART_HEIGHT * part} y2={CHART_HEIGHT * part} className="trend-grid" />
          <text x="-8" y={CHART_HEIGHT * part + 4} textAnchor="end" className="trend-axis">{new Intl.NumberFormat(getLocale(), { notation: 'compact', maximumFractionDigits: 1 }).format(max * (1 - part))}</text>
        </g>)}
        {children}
        <line x1={(selectedIndex + 0.5) * CHART_WIDTH / buckets.length} x2={(selectedIndex + 0.5) * CHART_WIDTH / buckets.length} y1="0" y2={CHART_HEIGHT} className="trend-cursor" />
      </g>
      <text x={PLOT_LEFT} y="184" className="trend-axis">{hourLabel(buckets[0].bucket_start)}</text>
      <text x={PLOT_LEFT + CHART_WIDTH} y="184" textAnchor="end" className="trend-axis">{hourLabel(buckets[buckets.length - 1].bucket_start)}</text>
    </svg>
  </div>
}

function Legend({ kind, children }: { kind: string; children: ReactNode }) {
  return <span><i className={`trend-key trend-${kind}`} />{children}</span>
}

function Lines({ values, max, kind }: { values: Array<number | null>; max: number; kind: string }) {
  return <g className={`trend-line trend-${kind}`}>{lineSegments(values, max, CHART_WIDTH, CHART_HEIGHT).map((points, index) => points.length === 1
    ? <circle key={index} cx={points[0][0]} cy={points[0][1]} r="2.5" />
    : <polyline key={index} points={points.map(([x, y]) => `${x},${y}`).join(' ')} />)}</g>
}

function TrendCharts({ buckets }: { buckets: TrendBucket[] }) {
  const [selectedHour, setSelectedHour] = useState<number | null>(null)
  const sliderId = useId()
  const matchedIndex = buckets.findIndex((bucket) => bucket.bucket_start === selectedHour)
  const selectedIndex = matchedIndex < 0 ? buckets.length - 1 : matchedIndex
  const selected = buckets[selectedIndex]
  const onSelect = (index: number) => setSelectedHour(buckets[index].bucket_start)
  const maxSamples = Math.max(1, ...buckets.map((bucket) => bucket.accepted_observation_samples))
  const maxEvents = Math.max(1, ...buckets.flatMap((bucket) => [bucket.path_switches, bucket.direct_failures, bucket.relay_failures]))
  const average = buckets.map((bucket) => bucket.validation_rtt_samples > 0 ? bucket.average_validation_rtt_ms ?? null : null)
  const p95 = buckets.map((bucket) => { const value = bucketP95(bucket); return value.kind === 'bound' ? value.value : null })
  const maxRTT = Math.max(1, ...average.map((value) => value ?? 0), ...p95.map((value) => value ?? 0))
  const p95Value = bucketP95(selected)
  const chartProps = { buckets, selectedIndex, onSelect }
  return <>
    <div className="trend-charts">
      <ChartFrame {...chartProps} title={tr('每小时路径观测样本')} max={maxSamples} legend={<><Legend kind="direct">Direct</Legend><Legend kind="relay">Relay</Legend><Legend kind="none">{tr('无路径')}</Legend></>}>
        {buckets.map((bucket, index) => {
          let below = 0
          return <g key={bucket.bucket_start}>{[
            ['direct', bucket.direct_observation_samples], ['relay', bucket.relay_observation_samples], ['none', bucket.no_path_observation_samples],
          ].map(([kind, value]) => {
            const height = Number(value) / maxSamples * CHART_HEIGHT
            below += height
            return <rect key={kind} className={`trend-bar trend-${kind}`} x={index * CHART_WIDTH / buckets.length} y={CHART_HEIGHT - below} width={Math.max(0.3, CHART_WIDTH / buckets.length - 0.5)} height={height} />
          })}</g>
        })}
      </ChartFrame>
      <ChartFrame {...chartProps} title={tr('每小时切换与失败')} max={maxEvents} legend={<><Legend kind="switch">{tr('切换')}</Legend><Legend kind="direct-failure">{tr('Direct 失败')}</Legend><Legend kind="relay-failure">{tr('Relay 失败')}</Legend></>}>
        <Lines values={buckets.map((bucket) => bucket.path_switches)} max={maxEvents} kind="switch" />
        <Lines values={buckets.map((bucket) => bucket.direct_failures)} max={maxEvents} kind="direct-failure" />
        <Lines values={buckets.map((bucket) => bucket.relay_failures)} max={maxEvents} kind="relay-failure" />
      </ChartFrame>
      <ChartFrame {...chartProps} title={tr('每小时验证 RTT（ms）')} max={maxRTT} legend={<><Legend kind="average">{tr('平均 RTT')}</Legend><Legend kind="p95">{tr('P95 分桶上界')}</Legend></>}>
        <Lines values={average} max={maxRTT} kind="average" />
        <Lines values={p95} max={maxRTT} kind="p95" />
        {buckets.map((bucket, index) => bucketP95(bucket).kind === 'overflow' && <text key={bucket.bucket_start} x={(index + 0.5) * CHART_WIDTH / buckets.length} y="8" textAnchor="middle" className="trend-overflow"><title>{tr('P95 超出 10000 ms 分桶上界')}</title>▲</text>)}
      </ChartFrame>
    </div>
    <div className="trend-hour-detail">
      <label htmlFor={sliderId}>{tr('查看小时明细')}<strong>{hourLabel(selected.bucket_start, true)}</strong></label>
      <input id={sliderId} type="range" min="0" max={buckets.length - 1} value={selectedIndex} onChange={(event) => onSelect(Number(event.target.value))} aria-valuetext={hourLabel(selected.bucket_start, true)} />
      <dl>
        <div><dt>{tr('观测样本')}</dt><dd>{count(selected.accepted_observation_samples)}</dd></div>
        <div><dt>{tr('Direct 样本占比')}</dt><dd>{selected.accepted_observation_samples > 0 ? `${(selected.direct_observation_samples / selected.accepted_observation_samples * 100).toFixed(1)}%` : '—'}</dd></div>
        <div><dt>{tr('切换')}</dt><dd>{count(selected.path_switches)}</dd></div>
        <div><dt>{tr('Direct / Relay 失败')}</dt><dd>{count(selected.direct_failures)} / {count(selected.relay_failures)}</dd></div>
        <div><dt>{tr('平均 RTT')}</dt><dd>{selected.validation_rtt_samples > 0 && selected.average_validation_rtt_ms !== undefined ? `${count(selected.average_validation_rtt_ms)} ms` : '—'}</dd></div>
        <div><dt>{tr('P95 分桶上界')}</dt><dd>{p95Value.kind === 'empty' ? '—' : p95Value.kind === 'overflow' ? '> 10,000 ms' : `≤ ${count(p95Value.value)} ms`}</dd></div>
      </dl>
      <span className="trend-detail-note">{tr('RTT 样本数')}：{count(selected.validation_rtt_samples)} · {tr('Direct / Relay / 无路径样本')}：{count(selected.direct_observation_samples)} / {count(selected.relay_observation_samples)} / {count(selected.no_path_observation_samples)}</span>
    </div>
  </>
}

export function ConnectionTrends({ networkId, windowHours, onWindowChange }: {
  networkId: string
  windowHours: number
  onWindowChange: (hours: number) => void
}) {
  const interval = useAutoRefresh(60_000)
  const result = useQuery({
    queryKey: ['connection-trends', networkId, windowHours],
    queryFn: ({ signal }) => connectionTrends(networkId, windowHours, signal),
    refetchInterval: interval,
  })
  const data = result.data
  const totals = data ? summarizeTrends(data.buckets) : null
  return <section className="panel-v2 connection-trends">
    <header className="panel-v2-header">
      <div><h2>{tr('连接历史趋势')}</h2><p>{tr('按小时汇总，当前小时尚未结束。时间按浏览器所在时区显示。')}</p></div>
      <div className="health-window-switch" role="group" aria-label={tr('趋势窗口')}>
        {TREND_WINDOWS.map((hours) => <button type="button" key={hours} className={windowHours === hours ? 'active' : ''} aria-pressed={windowHours === hours} onClick={() => onWindowChange(hours)}>{hours === 24 ? '24h' : hours === 168 ? '7d' : '30d'}</button>)}
      </div>
    </header>
    <div className="trend-body">
      <QueryStatus queries={[result]} />
      {!data ? result.fetchStatus === 'paused'
        ? <div className="trend-empty" role="status"><CircleAlert size={20} />{tr('浏览器当前离线，无法访问控制面。网络恢复后会自动重新请求。')}</div>
        : result.isPending
          ? <div className="loading-block" role="status"><div className="spinner" />{tr('正在读取历史趋势…')}</div>
          : <div className="error-block" role="alert"><CircleAlert size={18} /><div><strong>{tr('无法加载趋势')}</strong><span>{result.error instanceof Error ? tr(result.error.message) : tr('无法加载数据')}</span></div></div>
        : <>
          <div className="trend-totals">
            <div><span>{tr('观测样本')}</span><strong>{count(totals!.samples)}</strong></div>
            <div><span>{tr('Direct 样本占比')}</span><strong>{totals!.directShare === null ? '—' : `${(totals!.directShare * 100).toFixed(1)}%`}</strong></div>
            <div><span>{tr('切换')}</span><strong>{count(totals!.switches)}</strong></div>
            <div><span>{tr('显式路径失败')}</span><strong>{count(totals!.failures)}</strong></div>
          </div>
          {totals!.samples === 0 && <div className="trend-empty" role="status"><Activity size={19} /><span>{tr('此窗口没有已提交的观测样本；不代表路径在线或业务可达。')}</span></div>}
          {data.buckets.length > 0 && <TrendCharts key={`${networkId}:${windowHours}`} buckets={data.buckets} />}
          {totals!.rttSamples === 0 && <p className="trend-detail-note">{tr('此窗口没有 RTT 验证样本，图中保留空缺。')}</p>}
        </>}
      <p className="trend-semantics">{tr('样本占比不是在线时长、流量占比或 SLA。P95 是固定直方图的分桶上界，三角标记表示超过 10000 ms；没有样本的小时不会补成 0 ms。')}</p>
    </div>
  </section>
}
