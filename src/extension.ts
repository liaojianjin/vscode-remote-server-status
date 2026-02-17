import * as vscode from "vscode";
import * as os from "os";
import { promisify } from "util";
import { execFile } from "child_process";
import { readFile, access } from "fs/promises";

const execFileAsync = promisify(execFile);

const VIEW_ID = "remoteResourceMonitorView";
const CONFIG_SECTION = "remoteResourceMonitor";
const DEFAULT_PSEUDO_FILESYSTEMS = new Set([
  "tmpfs",
  "devtmpfs",
  "proc",
  "sysfs",
  "cgroup",
  "cgroup2",
  "devfs",
  "fusectl",
  "mqueue",
  "tracefs",
  "securityfs",
  "debugfs",
  "pstore",
  "autofs",
  "hugetlbfs",
  "rpc_pipefs",
  "binfmt_misc",
  "nsfs"
]);
const SPARKLINE_CHARS = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

type AlertLevel = "normal" | "warning" | "critical";
type AlertMetricName = "CPU" | "Memory" | "Disk";
type DiskDisplayMode = "percent" | "remaining" | "remainingAndTotal";

interface CpuTickSnapshot {
  idle: number;
  total: number;
}

interface DiskUsage {
  filesystem: string;
  fsType?: string;
  usedBytes: number;
  availableBytes: number;
  totalBytes: number;
  mountPoint: string;
}

interface MemoryUsage {
  usedBytes: number;
  totalBytes: number;
  source: "host" | "cgroup";
}

interface RuntimeContext {
  location: "Server" | "Container";
  hint?: string;
  cpuLimitCores?: number;
}

interface ResourceSnapshot {
  timestamp: Date;
  cpuPercent?: number;
  memory?: MemoryUsage;
  disks: DiskUsage[];
  context: RuntimeContext;
  hostname: string;
}

interface ThresholdPair {
  warning: number;
  critical: number;
}

interface MonitorConfig {
  refreshIntervalMs: number;
  historyPoints: number;
  maxDisks: number;
  diskMountPoints: string[];
  diskAliases: Record<string, string>;
  diskDisplayMode: DiskDisplayMode;
  includePseudoFilesystems: boolean;
  monitor: {
    cpu: boolean;
    memory: boolean;
    disk: boolean;
  };
  statusBar: {
    showCpu: boolean;
    showMemory: boolean;
    showDisk: boolean;
  };
  thresholds: {
    cpu: ThresholdPair;
    memory: ThresholdPair;
    disk: ThresholdPair;
  };
  enableNotifications: boolean;
  notifyCooldownMs: number;
}

interface TrendSeries {
  cpu: number[];
  memory: number[];
  disk: number[];
}

interface MetricAlert {
  metric: AlertMetricName;
  level: AlertLevel;
  value: number;
  warning: number;
  critical: number;
}

interface AlertState {
  overall: AlertLevel;
  metrics: MetricAlert[];
}

class ResourceCollector {
  private previousCpu?: CpuTickSnapshot;

  public async collect(config: MonitorConfig): Promise<ResourceSnapshot> {
    const context = await this.detectRuntimeContext();
    const [disks, memory] = await Promise.all([
      config.monitor.disk ? this.readDiskUsages(config) : Promise.resolve([]),
      config.monitor.memory ? this.readMemoryUsage() : Promise.resolve(undefined)
    ]);

    const cpuPercent = config.monitor.cpu
      ? this.readCpuUsagePercent()
      : undefined;

    if (!config.monitor.cpu) {
      this.previousCpu = undefined;
    }

    return {
      timestamp: new Date(),
      cpuPercent,
      memory,
      disks,
      context,
      hostname: os.hostname()
    };
  }

  private readCpuUsagePercent(): number {
    const current = this.readCpuSnapshot();
    if (!this.previousCpu) {
      this.previousCpu = current;
      return 0;
    }

    const idleDelta = current.idle - this.previousCpu.idle;
    const totalDelta = current.total - this.previousCpu.total;
    this.previousCpu = current;

    if (totalDelta <= 0) {
      return 0;
    }

    const ratio = 1 - idleDelta / totalDelta;
    return clampPercent(ratio * 100);
  }

  private readCpuSnapshot(): CpuTickSnapshot {
    const cpus = os.cpus();
    let idle = 0;
    let total = 0;

    for (const cpu of cpus) {
      idle += cpu.times.idle;
      total += cpu.times.user + cpu.times.nice + cpu.times.sys + cpu.times.idle + cpu.times.irq;
    }

    return { idle, total };
  }

  private async readDiskUsages(config: MonitorConfig): Promise<DiskUsage[]> {
    const parsed = await this.tryReadDiskUsage(true) ?? await this.tryReadDiskUsage(false) ?? [];
    const byType = config.includePseudoFilesystems
      ? parsed
      : parsed.filter((disk) => !disk.fsType || !DEFAULT_PSEUDO_FILESYSTEMS.has(disk.fsType));

    if (config.diskMountPoints.length > 0) {
      const mountOrder = new Map(config.diskMountPoints.map((mount, index) => [mount, index]));
      return byType
        .filter((disk) => mountOrder.has(disk.mountPoint))
        .sort((a, b) => (mountOrder.get(a.mountPoint) ?? 0) - (mountOrder.get(b.mountPoint) ?? 0));
    }

    const sorted = [...byType]
      .filter((disk) => disk.totalBytes > 0)
      .sort((a, b) => getDiskPercent(b) - getDiskPercent(a));

    return includeRootDisk(sorted, config.maxDisks);
  }

  private async tryReadDiskUsage(includeType: boolean): Promise<DiskUsage[] | undefined> {
    try {
      const args = includeType ? ["-kPT"] : ["-kP"];
      const { stdout } = await execFileAsync("df", args, {
        timeout: 3000,
        maxBuffer: 256 * 1024,
        encoding: "utf8"
      });
      return this.parseDf(stdout, includeType);
    } catch {
      return undefined;
    }
  }

  private parseDf(stdout: string, includeType: boolean): DiskUsage[] {
    const lines = stdout.trim().split(/\r?\n/).filter(Boolean);
    if (lines.length <= 1) {
      return [];
    }

    const disks: DiskUsage[] = [];
    for (const line of lines.slice(1)) {
      const parts = line.trim().split(/\s+/);
      if (includeType) {
        if (parts.length < 7) {
          continue;
        }
        const filesystem = parts[0];
        const fsType = parts[1];
        const totalKb = Number(parts[2]);
        const usedKb = Number(parts[3]);
        const availKb = Number(parts[4]);
        const mountPoint = parts.slice(6).join(" ");
        if (!Number.isFinite(totalKb) || !Number.isFinite(usedKb) || !Number.isFinite(availKb) || totalKb <= 0) {
          continue;
        }

        disks.push({
          filesystem,
          fsType,
          usedBytes: usedKb * 1024,
          availableBytes: availKb * 1024,
          totalBytes: totalKb * 1024,
          mountPoint
        });
        continue;
      }

      if (parts.length < 6) {
        continue;
      }
      const filesystem = parts[0];
      const totalKb = Number(parts[1]);
      const usedKb = Number(parts[2]);
      const availKb = Number(parts[3]);
      const mountPoint = parts.slice(5).join(" ");
      if (!Number.isFinite(totalKb) || !Number.isFinite(usedKb) || !Number.isFinite(availKb) || totalKb <= 0) {
        continue;
      }

      disks.push({
        filesystem,
        usedBytes: usedKb * 1024,
        availableBytes: availKb * 1024,
        totalBytes: totalKb * 1024,
        mountPoint
      });
    }

    return disks;
  }

  private async readMemoryUsage(): Promise<MemoryUsage> {
    if (process.platform === "linux") {
      const cgroup = await this.readCgroupMemoryUsage();
      if (cgroup) {
        return {
          usedBytes: cgroup.usedBytes,
          totalBytes: cgroup.totalBytes,
          source: "cgroup"
        };
      }
    }

    const totalBytes = os.totalmem();
    return {
      usedBytes: totalBytes - os.freemem(),
      totalBytes,
      source: "host"
    };
  }

  private async readCgroupMemoryUsage(): Promise<{ usedBytes: number; totalBytes: number } | undefined> {
    const v2 = await this.tryReadCgroupFiles("/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.max");
    if (v2) {
      return v2;
    }

    return this.tryReadCgroupFiles(
      "/sys/fs/cgroup/memory/memory.usage_in_bytes",
      "/sys/fs/cgroup/memory/memory.limit_in_bytes"
    );
  }

  private async tryReadCgroupFiles(usedPath: string, limitPath: string): Promise<{ usedBytes: number; totalBytes: number } | undefined> {
    const [usedRaw, limitRaw] = await Promise.all([this.safeRead(usedPath), this.safeRead(limitPath)]);
    if (!usedRaw || !limitRaw) {
      return undefined;
    }

    const usedValue = Number(usedRaw);
    if (!Number.isFinite(usedValue) || usedValue < 0) {
      return undefined;
    }

    if (limitRaw === "max") {
      return undefined;
    }

    const limitValue = Number(limitRaw);
    if (!Number.isFinite(limitValue) || limitValue <= 0) {
      return undefined;
    }

    if (limitValue > os.totalmem() * 64) {
      return undefined;
    }

    return {
      usedBytes: Math.min(usedValue, limitValue),
      totalBytes: limitValue
    };
  }

  private async detectRuntimeContext(): Promise<RuntimeContext> {
    if (process.platform !== "linux") {
      return { location: "Server" };
    }

    const [cgroup, dockerEnv, cpuLimit] = await Promise.all([
      this.safeRead("/proc/1/cgroup"),
      this.pathExists("/.dockerenv"),
      this.readCpuLimitCores()
    ]);

    const containerPattern = /(docker|kubepods|containerd|podman|lxc|libpod)/i;
    if (dockerEnv) {
      return { location: "Container", hint: "detected by /.dockerenv", cpuLimitCores: cpuLimit };
    }

    if (cgroup && containerPattern.test(cgroup)) {
      return { location: "Container", hint: "detected by /proc/1/cgroup", cpuLimitCores: cpuLimit };
    }

    return { location: "Server", cpuLimitCores: cpuLimit };
  }

  private async readCpuLimitCores(): Promise<number | undefined> {
    if (process.platform !== "linux") {
      return undefined;
    }

    const cpuMax = await this.safeRead("/sys/fs/cgroup/cpu.max");
    if (cpuMax) {
      const [quotaRaw, periodRaw] = cpuMax.split(/\s+/);
      if (quotaRaw && periodRaw && quotaRaw !== "max") {
        const quota = Number(quotaRaw);
        const period = Number(periodRaw);
        if (Number.isFinite(quota) && Number.isFinite(period) && quota > 0 && period > 0) {
          return quota / period;
        }
      }
    }

    const [quotaRaw, periodRaw] = await Promise.all([
      this.safeRead("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"),
      this.safeRead("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    ]);

    if (!quotaRaw || !periodRaw) {
      return undefined;
    }

    const quota = Number(quotaRaw);
    const period = Number(periodRaw);
    if (!Number.isFinite(quota) || !Number.isFinite(period) || quota <= 0 || period <= 0) {
      return undefined;
    }

    return quota / period;
  }

  private async safeRead(filePath: string): Promise<string | undefined> {
    try {
      const value = await readFile(filePath, "utf8");
      return value.trim();
    } catch {
      return undefined;
    }
  }

  private async pathExists(filePath: string): Promise<boolean> {
    try {
      await access(filePath);
      return true;
    } catch {
      return false;
    }
  }
}

class TrendStore {
  private cpu: number[] = [];
  private memory: number[] = [];
  private disk: number[] = [];

  constructor(private maxPoints: number) {}

  public setMaxPoints(maxPoints: number): void {
    this.maxPoints = Math.max(5, maxPoints);
    this.trim();
  }

  public push(snapshot: ResourceSnapshot, config: MonitorConfig): void {
    const memoryPercent = getMemoryPercent(snapshot.memory);
    const diskPercent = getHighestDiskPercent(snapshot.disks);

    if (config.monitor.cpu && snapshot.cpuPercent !== undefined) {
      this.cpu.push(clampPercent(snapshot.cpuPercent));
    } else {
      this.cpu = [];
    }

    if (config.monitor.memory && memoryPercent !== undefined) {
      this.memory.push(clampPercent(memoryPercent));
    } else {
      this.memory = [];
    }

    if (config.monitor.disk) {
      this.disk.push(diskPercent === undefined ? 0 : clampPercent(diskPercent));
    } else {
      this.disk = [];
    }

    this.trim();
  }

  public series(): TrendSeries {
    return {
      cpu: [...this.cpu],
      memory: [...this.memory],
      disk: [...this.disk]
    };
  }

  private trim(): void {
    this.cpu = trimArray(this.cpu, this.maxPoints);
    this.memory = trimArray(this.memory, this.maxPoints);
    this.disk = trimArray(this.disk, this.maxPoints);
  }
}

class AlertManager {
  private lastLevels: Record<AlertMetricName, AlertLevel> = {
    CPU: "normal",
    Memory: "normal",
    Disk: "normal"
  };
  private lastNotificationAt = 0;

  public evaluate(snapshot: ResourceSnapshot, config: MonitorConfig): AlertState {
    const memoryPercent = getMemoryPercent(snapshot.memory) ?? 0;
    const highestDiskPercent = getHighestDiskPercent(snapshot.disks) ?? 0;

    const cpuAlert = config.monitor.cpu && snapshot.cpuPercent !== undefined
      ? this.buildMetricAlert("CPU", snapshot.cpuPercent, config.thresholds.cpu)
      : this.normalMetricAlert("CPU", config.thresholds.cpu);
    const memoryAlert = config.monitor.memory && snapshot.memory !== undefined
      ? this.buildMetricAlert("Memory", memoryPercent, config.thresholds.memory)
      : this.normalMetricAlert("Memory", config.thresholds.memory);
    const diskAlert = config.monitor.disk
      ? this.buildMetricAlert("Disk", highestDiskPercent, config.thresholds.disk)
      : this.normalMetricAlert("Disk", config.thresholds.disk);

    const metrics = [cpuAlert, memoryAlert, diskAlert].filter((item) => item.level !== "normal");
    const overall = maxLevel([cpuAlert.level, memoryAlert.level, diskAlert.level]);

    return { overall, metrics };
  }

  public notifyIfNeeded(alert: AlertState, config: MonitorConfig): void {
    const nextLevels: Record<AlertMetricName, AlertLevel> = {
      CPU: metricLevel(alert, "CPU"),
      Memory: metricLevel(alert, "Memory"),
      Disk: metricLevel(alert, "Disk")
    };

    const escalatedMetrics = (Object.keys(nextLevels) as AlertMetricName[])
      .filter((metric) => levelRank(nextLevels[metric]) > levelRank(this.lastLevels[metric]));

    const now = Date.now();
    const canNotify = config.enableNotifications && now - this.lastNotificationAt >= config.notifyCooldownMs;
    if (canNotify && escalatedMetrics.length > 0) {
      const alerts = alert.metrics.filter((item) => escalatedMetrics.includes(item.metric));
      const detail = alerts
        .map((item) => `${item.metric} ${formatPercent(item.value)} (W:${item.warning}% C:${item.critical}%)`)
        .join(" | ");

      if (alert.overall === "critical") {
        void vscode.window.showErrorMessage(`Remote Resource Monitor 告警: ${detail}`);
      } else {
        void vscode.window.showWarningMessage(`Remote Resource Monitor 告警: ${detail}`);
      }
      this.lastNotificationAt = now;
    }

    this.lastLevels = nextLevels;
  }

  private buildMetricAlert(metric: AlertMetricName, value: number, thresholds: ThresholdPair): MetricAlert {
    return {
      metric,
      value,
      warning: thresholds.warning,
      critical: thresholds.critical,
      level: resolveLevel(value, thresholds)
    };
  }

  private normalMetricAlert(metric: AlertMetricName, thresholds: ThresholdPair): MetricAlert {
    return {
      metric,
      value: 0,
      warning: thresholds.warning,
      critical: thresholds.critical,
      level: "normal"
    };
  }
}

class MetricItem extends vscode.TreeItem {
  constructor(label: string, description: string, tooltip: string) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.description = description;
    this.tooltip = tooltip;
  }
}

class MetricsTreeDataProvider implements vscode.TreeDataProvider<MetricItem> {
  private readonly emitter = new vscode.EventEmitter<MetricItem | undefined | null | void>();
  public readonly onDidChangeTreeData = this.emitter.event;

  private snapshot?: ResourceSnapshot;
  private trends?: TrendSeries;
  private alert?: AlertState;
  private config?: MonitorConfig;
  private errorMessage?: string;

  public setSnapshot(snapshot: ResourceSnapshot, trends: TrendSeries, alert: AlertState, config: MonitorConfig): void {
    this.snapshot = snapshot;
    this.trends = trends;
    this.alert = alert;
    this.config = config;
    this.errorMessage = undefined;
    this.emitter.fire(undefined);
  }

  public setConfig(config: MonitorConfig): void {
    this.config = config;
    this.emitter.fire(undefined);
  }

  public setError(errorMessage: string): void {
    this.errorMessage = errorMessage;
    this.emitter.fire(undefined);
  }

  public getTreeItem(element: MetricItem): vscode.TreeItem {
    return element;
  }

  public getChildren(_element?: MetricItem): MetricItem[] {
    if (this.errorMessage) {
      return [new MetricItem("采集失败", this.errorMessage, this.errorMessage)];
    }

    if (!this.snapshot || !this.trends || !this.alert || !this.config) {
      return [new MetricItem("初始化中", "正在采集远程指标", "正在采集远程指标")];
    }

    const items: MetricItem[] = [];
    const memoryPercent = getMemoryPercent(this.snapshot.memory);
    const topDisk = getHighestDisk(this.snapshot.disks);

    items.push(new MetricItem("告警级别", formatLevel(this.alert.overall), formatAlertTooltip(this.alert)));

    if (this.config.monitor.cpu) {
      const cpuPercent = this.snapshot.cpuPercent ?? 0;
      items.push(new MetricItem("CPU 利用率", formatPercent(cpuPercent), `CPU 当前值: ${formatPercent(cpuPercent)}`));
      items.push(new MetricItem("CPU 趋势", `${toSparkline(this.trends.cpu)} ${formatPercent(last(this.trends.cpu) ?? 0)}`, "最近采样点趋势"));
    } else {
      items.push(new MetricItem("CPU 监控", "已关闭", "在设置中开启 remoteResourceMonitor.monitorCpu"));
    }

    if (this.config.monitor.memory && this.snapshot.memory && memoryPercent !== undefined) {
      items.push(new MetricItem(
        "内存使用",
        `${formatPercent(memoryPercent)} (${formatBytes(this.snapshot.memory.usedBytes)} / ${formatBytes(this.snapshot.memory.totalBytes)})`,
        `内存来源: ${this.snapshot.memory.source === "cgroup" ? "容器 cgroup" : "主机"}`
      ));
      items.push(new MetricItem("内存趋势", `${toSparkline(this.trends.memory)} ${formatPercent(last(this.trends.memory) ?? 0)}`, "最近采样点趋势"));
    } else if (!this.config.monitor.memory) {
      items.push(new MetricItem("内存监控", "已关闭", "在设置中开启 remoteResourceMonitor.monitorMemory"));
    } else {
      items.push(new MetricItem("内存", "不可用", "当前未能读取内存指标"));
    }

    if (this.config.monitor.disk) {
      items.push(new MetricItem(
        "磁盘趋势(最高占用)",
        `${toSparkline(this.trends.disk)} ${formatPercent(last(this.trends.disk) ?? 0)}`,
        "最近采样点趋势"
      ));
    } else {
      items.push(new MetricItem("磁盘监控", "已关闭", "在设置中开启 remoteResourceMonitor.monitorDisk"));
    }

    if (!this.config.monitor.disk) {
      items.push(new MetricItem("磁盘", "监控已关闭", "在设置中开启 remoteResourceMonitor.monitorDisk"));
    } else if (this.snapshot.disks.length === 0) {
      items.push(new MetricItem("磁盘", "不可用", "无法读取 df 输出或未匹配到挂载点"));
    } else {
      for (const disk of this.snapshot.disks) {
        const diskName = getDiskDisplayName(disk, this.config);
        items.push(new MetricItem(
          `磁盘 ${diskName}`,
          formatDiskDescription(disk, this.config.diskDisplayMode),
          `挂载点: ${disk.mountPoint}\n设备: ${disk.filesystem}${disk.fsType ? ` | 类型: ${disk.fsType}` : ""}`
        ));
      }
    }

    if (this.config.monitor.disk && topDisk) {
      items.push(new MetricItem(
        "最高占用磁盘",
        `${getDiskDisplayName(topDisk, this.config)} (${formatPercent(getDiskPercent(topDisk))})`,
        `挂载点: ${topDisk.mountPoint}\n设备: ${topDisk.filesystem}`
      ));
    }

    const cpuLimit = this.snapshot.context.cpuLimitCores
      ? `${this.snapshot.context.cpuLimitCores.toFixed(2)} 核`
      : "未限制";
    items.push(new MetricItem("运行环境", this.snapshot.context.location, this.snapshot.context.hint ?? this.snapshot.context.location));
    items.push(new MetricItem("CPU 配额", cpuLimit, "容器环境下读取 cgroup CPU 配额"));
    items.push(new MetricItem("主机名", this.snapshot.hostname, this.snapshot.hostname));
    items.push(new MetricItem("更新时间", this.snapshot.timestamp.toLocaleTimeString(), this.snapshot.timestamp.toISOString()));

    return items;
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel("Remote Resource Monitor");
  const collector = new ResourceCollector();
  let config = readMonitorConfig();
  const trendStore = new TrendStore(config.historyPoints);
  const alertManager = new AlertManager();
  const treeProvider = new MetricsTreeDataProvider();
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 80);

  statusBar.name = "Remote Resource Monitor";
  statusBar.command = "remoteResourceMonitor.refresh";
  statusBar.text = "$(pulse) CPU -- | MEM -- | DISK --";
  statusBar.tooltip = "Remote Resource Monitor";
  statusBar.show();

  const treeDisposable = vscode.window.registerTreeDataProvider(VIEW_ID, treeProvider);
  context.subscriptions.push(treeDisposable, output, statusBar);
  treeProvider.setConfig(config);

  const refresh = async (): Promise<void> => {
    try {
      const snapshot = await collector.collect(config);
      trendStore.push(snapshot, config);
      const trends = trendStore.series();
      const alert = alertManager.evaluate(snapshot, config);
      alertManager.notifyIfNeeded(alert, config);

      treeProvider.setSnapshot(snapshot, trends, alert, config);
      updateStatusBar(statusBar, snapshot, trends, alert, config);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      treeProvider.setError(message);
      statusBar.text = "$(warning) Remote Monitor Error";
      statusBar.tooltip = message;
      statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
      statusBar.color = undefined;
      output.appendLine(`[${new Date().toISOString()}] ${message}`);
    }
  };

  const refreshCommand = vscode.commands.registerCommand("remoteResourceMonitor.refresh", async () => {
    await refresh();
  });
  context.subscriptions.push(refreshCommand);

  let timer: NodeJS.Timeout | undefined;
  const restartTimer = (): void => {
    if (timer) {
      clearInterval(timer);
    }
    timer = setInterval(() => {
      void refresh();
    }, config.refreshIntervalMs);
  };

  restartTimer();
  context.subscriptions.push(new vscode.Disposable(() => {
    if (timer) {
      clearInterval(timer);
    }
  }));

  const configChange = vscode.workspace.onDidChangeConfiguration((event) => {
    if (!event.affectsConfiguration(CONFIG_SECTION)) {
      return;
    }

    config = readMonitorConfig();
    trendStore.setMaxPoints(config.historyPoints);
    treeProvider.setConfig(config);
    restartTimer();
    void refresh();
  });
  context.subscriptions.push(configChange);

  void refresh();
}

export function deactivate(): void {
  // no-op
}

function updateStatusBar(
  statusBar: vscode.StatusBarItem,
  snapshot: ResourceSnapshot,
  trends: TrendSeries,
  alert: AlertState,
  config: MonitorConfig
): void {
  const memoryPercent = getMemoryPercent(snapshot.memory);
  const diskText = !config.monitor.disk
    ? "OFF"
    : snapshot.disks.length === 0
      ? "--"
      : snapshot.disks
        .map((disk) => `${getDiskDisplayName(disk, config)} ${formatDiskValue(disk, config.diskDisplayMode)}`)
        .join(", ");

  const icon = alert.overall === "critical"
    ? "$(error)"
    : alert.overall === "warning"
      ? "$(warning)"
      : "$(pulse)";

  const segments: string[] = [];
  if (config.statusBar.showCpu) {
    segments.push(`CPU ${config.monitor.cpu && snapshot.cpuPercent !== undefined ? formatPercent(snapshot.cpuPercent) : "OFF"}`);
  }
  if (config.statusBar.showMemory) {
    segments.push(`MEM ${config.monitor.memory && memoryPercent !== undefined ? formatPercent(memoryPercent) : "OFF"}`);
  }
  if (config.statusBar.showDisk) {
    segments.push(`DISK ${diskText}`);
  }

  const textBody = segments.length > 0 ? segments.join(" | ") : "Remote Monitor";
  statusBar.text = `${icon} ${textBody}`;

  const alertLine = alert.metrics.length === 0
    ? "Alerts: none"
    : `Alerts: ${alert.metrics.map((item) => `${item.metric} ${formatLevel(item.level)} ${formatPercent(item.value)}`).join(" | ")}`;

  const diskLines = snapshot.disks.length === 0
    ? ["Disk: unavailable"]
    : snapshot.disks.map((disk) => {
      const name = getDiskDisplayName(disk, config);
      return `Disk ${name} (${disk.mountPoint}): ${formatDiskDescription(disk, config.diskDisplayMode)}`;
    });

  const cpuTooltip = config.monitor.cpu && snapshot.cpuPercent !== undefined
    ? `CPU: ${formatPercent(snapshot.cpuPercent)} | ${toSparkline(trends.cpu)}`
    : "CPU: monitoring disabled";
  const memoryTooltip = config.monitor.memory && memoryPercent !== undefined
    ? `MEM: ${formatPercent(memoryPercent)} | ${toSparkline(trends.memory)}`
    : "MEM: monitoring disabled";
  const diskTooltip = config.monitor.disk
    ? `DSK: ${formatPercent(getHighestDiskPercent(snapshot.disks) ?? 0)} | ${toSparkline(trends.disk)}`
    : "DSK: monitoring disabled";

  statusBar.tooltip = [
    `Host: ${snapshot.hostname}`,
    `Runtime: ${snapshot.context.location}`,
    alertLine,
    cpuTooltip,
    memoryTooltip,
    diskTooltip,
    ...(config.monitor.disk ? diskLines : [])
  ].join("\n");

  applyStatusBarSeverity(statusBar, alert.overall);
}

function applyStatusBarSeverity(statusBar: vscode.StatusBarItem, level: AlertLevel): void {
  if (level === "critical") {
    statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
    statusBar.color = new vscode.ThemeColor("statusBarItem.errorForeground");
    return;
  }

  if (level === "warning") {
    statusBar.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    statusBar.color = undefined;
    return;
  }

  statusBar.backgroundColor = undefined;
  statusBar.color = undefined;
}

function readMonitorConfig(): MonitorConfig {
  const config = vscode.workspace.getConfiguration(CONFIG_SECTION);

  const mountPointsRaw = config.get<unknown>("diskMountPoints", []);
  const diskMountPoints = Array.isArray(mountPointsRaw)
    ? mountPointsRaw.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];

  const refreshIntervalSeconds = clampNumber(config.get<number>("refreshIntervalSeconds", 5), 1, 3600);
  const historyPoints = clampNumber(config.get<number>("historyPoints", 24), 5, 200);
  const maxDisks = clampNumber(config.get<number>("maxDisks", 6), 1, 32);
  const diskAliases = parseDiskAliases(config.get<unknown>("diskAliases", {}));
  const diskDisplayMode = parseDiskDisplayMode(config.get<string>("diskDisplayMode", "percent"));

  const cpuWarning = clampNumber(config.get<number>("cpuWarningPercent", 75), 1, 99);
  const cpuCritical = clampNumber(config.get<number>("cpuCriticalPercent", 90), cpuWarning + 1, 100);
  const memoryWarning = clampNumber(config.get<number>("memoryWarningPercent", 75), 1, 99);
  const memoryCritical = clampNumber(config.get<number>("memoryCriticalPercent", 90), memoryWarning + 1, 100);
  const diskWarning = clampNumber(config.get<number>("diskWarningPercent", 80), 1, 99);
  const diskCritical = clampNumber(config.get<number>("diskCriticalPercent", 92), diskWarning + 1, 100);

  const notifyCooldownSeconds = clampNumber(config.get<number>("notifyCooldownSeconds", 120), 10, 3600);

  return {
    refreshIntervalMs: refreshIntervalSeconds * 1000,
    historyPoints,
    maxDisks,
    diskMountPoints,
    diskAliases,
    diskDisplayMode,
    includePseudoFilesystems: config.get<boolean>("includePseudoFilesystems", false),
    monitor: {
      cpu: config.get<boolean>("monitorCpu", true),
      memory: config.get<boolean>("monitorMemory", true),
      disk: config.get<boolean>("monitorDisk", true)
    },
    statusBar: {
      showCpu: config.get<boolean>("showCpuInStatusBar", true),
      showMemory: config.get<boolean>("showMemoryInStatusBar", true),
      showDisk: config.get<boolean>("showDiskInStatusBar", true)
    },
    thresholds: {
      cpu: { warning: cpuWarning, critical: cpuCritical },
      memory: { warning: memoryWarning, critical: memoryCritical },
      disk: { warning: diskWarning, critical: diskCritical }
    },
    enableNotifications: config.get<boolean>("enableNotifications", true),
    notifyCooldownMs: notifyCooldownSeconds * 1000
  };
}

function includeRootDisk(sortedByUsage: DiskUsage[], maxDisks: number): DiskUsage[] {
  const selected = sortedByUsage.slice(0, maxDisks);
  if (selected.some((disk) => disk.mountPoint === "/")) {
    return selected;
  }

  const root = sortedByUsage.find((disk) => disk.mountPoint === "/");
  if (!root) {
    return selected;
  }

  if (selected.length < maxDisks) {
    return [...selected, root];
  }

  return [...selected.slice(0, Math.max(0, selected.length - 1)), root];
}

function metricLevel(alert: AlertState, metric: AlertMetricName): AlertLevel {
  return alert.metrics.find((item) => item.metric === metric)?.level ?? "normal";
}

function resolveLevel(value: number, thresholds: ThresholdPair): AlertLevel {
  if (value >= thresholds.critical) {
    return "critical";
  }
  if (value >= thresholds.warning) {
    return "warning";
  }
  return "normal";
}

function maxLevel(levels: AlertLevel[]): AlertLevel {
  let current: AlertLevel = "normal";
  for (const level of levels) {
    if (levelRank(level) > levelRank(current)) {
      current = level;
    }
  }
  return current;
}

function levelRank(level: AlertLevel): number {
  if (level === "critical") {
    return 2;
  }
  if (level === "warning") {
    return 1;
  }
  return 0;
}

function formatAlertTooltip(alert: AlertState): string {
  if (alert.metrics.length === 0) {
    return "当前无告警";
  }

  return alert.metrics
    .map((item) => `${item.metric} ${formatLevel(item.level)}: ${formatPercent(item.value)} (W:${item.warning}% C:${item.critical}%)`)
    .join("\n");
}

function formatLevel(level: AlertLevel): string {
  if (level === "critical") {
    return "严重";
  }
  if (level === "warning") {
    return "预警";
  }
  return "正常";
}

function getDiskPercent(disk: DiskUsage): number {
  if (disk.totalBytes <= 0) {
    return 0;
  }
  return clampPercent((disk.usedBytes / disk.totalBytes) * 100);
}

function getHighestDisk(disks: DiskUsage[]): DiskUsage | undefined {
  if (disks.length === 0) {
    return undefined;
  }

  return disks.reduce((current, disk) => getDiskPercent(disk) > getDiskPercent(current) ? disk : current);
}

function getHighestDiskPercent(disks: DiskUsage[]): number | undefined {
  const disk = getHighestDisk(disks);
  return disk ? getDiskPercent(disk) : undefined;
}

function getMemoryPercent(memory: MemoryUsage | undefined): number | undefined {
  if (!memory || memory.totalBytes <= 0) {
    return undefined;
  }
  return clampPercent((memory.usedBytes / memory.totalBytes) * 100);
}

function toSparkline(values: number[]): string {
  if (values.length === 0) {
    return "--";
  }

  return values
    .map((raw) => {
      const value = clampPercent(raw);
      const index = Math.min(SPARKLINE_CHARS.length - 1, Math.floor(value / (100 / SPARKLINE_CHARS.length)));
      return SPARKLINE_CHARS[index];
    })
    .join("");
}

function clampPercent(value: number): number {
  if (!Number.isFinite(value)) {
    return 0;
  }
  return Math.max(0, Math.min(100, value));
}

function formatPercent(value: number): string {
  return `${clampPercent(value).toFixed(1)}%`;
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) {
    return "N/A";
  }

  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }

  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function getDiskDisplayName(disk: DiskUsage, config: MonitorConfig): string {
  const aliasFromMount = config.diskAliases[disk.mountPoint];
  if (aliasFromMount) {
    return aliasFromMount;
  }

  const aliasFromFilesystem = config.diskAliases[disk.filesystem];
  if (aliasFromFilesystem) {
    return aliasFromFilesystem;
  }

  return shortMountPoint(disk.mountPoint);
}

function formatDiskValue(disk: DiskUsage, mode: DiskDisplayMode): string {
  if (mode === "remaining") {
    return `${formatBytes(disk.availableBytes)} free`;
  }

  if (mode === "remainingAndTotal") {
    return `${formatBytes(disk.availableBytes)} free / ${formatBytes(disk.totalBytes)}`;
  }

  return formatPercent(getDiskPercent(disk));
}

function formatDiskDescription(disk: DiskUsage, mode: DiskDisplayMode): string {
  const percent = formatPercent(getDiskPercent(disk));
  if (mode === "remaining") {
    return `剩余 ${formatBytes(disk.availableBytes)} (已用 ${percent})`;
  }

  if (mode === "remainingAndTotal") {
    return `剩余 ${formatBytes(disk.availableBytes)} / 总计 ${formatBytes(disk.totalBytes)} (已用 ${percent})`;
  }

  return `${percent} (${formatBytes(disk.usedBytes)} / ${formatBytes(disk.totalBytes)})`;
}

function shortMountPoint(mountPoint: string): string {
  if (mountPoint.length <= 12) {
    return mountPoint;
  }
  return `...${mountPoint.slice(-9)}`;
}

function parseDiskAliases(raw: unknown): Record<string, string> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return {};
  }

  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (typeof key !== "string" || typeof value !== "string") {
      continue;
    }

    const normalizedKey = key.trim();
    const normalizedValue = value.trim();
    if (!normalizedKey || !normalizedValue) {
      continue;
    }

    result[normalizedKey] = normalizedValue;
  }

  return result;
}

function parseDiskDisplayMode(raw: string): DiskDisplayMode {
  if (raw === "remaining" || raw === "remainingAndTotal" || raw === "percent") {
    return raw;
  }

  return "percent";
}

function trimArray(values: number[], max: number): number[] {
  if (values.length <= max) {
    return values;
  }
  return values.slice(values.length - max);
}

function last<T>(values: T[]): T | undefined {
  return values.length > 0 ? values[values.length - 1] : undefined;
}

function clampNumber(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }
  return Math.max(min, Math.min(max, value));
}
