# Remote Server Status (VS Code Extension)

在 VS Code 的远程连接场景（Remote SSH / Dev Containers）下，显示当前远程环境的资源状态：

- CPU 利用率
- 内存使用率与容量
- 多磁盘挂载点使用率与容量（支持指定挂载点或自动选择 Top N）
- 历史趋势小图（CPU / 内存 / 磁盘）
- 阈值告警（状态栏变色 + VS Code 通知）

## 展示位置

- 状态栏（推荐主入口）：显示 `CPU | MEM | DISK` 实时摘要，点击可手动刷新。
- 状态栏颜色：正常无底色，预警为 warning 背景，严重告警为 error 背景。
- Explorer 侧边栏视图：显示详情指标、各挂载点容量、趋势小图、告警级别等。

这样做的原因是：

- 状态栏适合持续观察，信息密度高且不打断编码。
- 侧边栏适合查看详情，不会占用编辑区。

## 如何运行

1. 安装依赖

```bash
npm install
```

2. 编译

```bash
npm run compile
```

3. 在 VS Code 中按 `F5` 启动 Extension Development Host。
4. 在新窗口连接远程 SSH 或容器后，查看：
   - 底部状态栏：`CPU | MEM | DISK`
   - Explorer: `Remote Resource Monitor` 视图

## 技术说明

- 扩展运行在 `workspace` extension host（远程连接时运行在远端），因此采集到的是当前远端环境的数据。
- CPU 通过 `os.cpus()` 的时间片增量计算利用率。
- 内存优先读取 Linux cgroup（容器场景），失败时回退到主机内存。
- 磁盘通过 `df -kPT`（fallback `df -kP`）读取并解析多挂载点。

## 可配置项

可在 VS Code Settings 中搜索 `remoteResourceMonitor`：

- `refreshIntervalSeconds`: 刷新间隔秒数
- `historyPoints`: 趋势图采样点数
- `maxDisks`: 未指定挂载点时，最多展示的磁盘数量
- `diskMountPoints`: 指定要监控的挂载点，例如 `['/', '/data']`
- `diskAliases`: 磁盘名称别名映射（key 可填挂载点或设备名，value 是短名称）
- `diskDisplayMode`: 磁盘显示模式（`percent` / `remaining` / `remainingAndTotal`）
- `includePseudoFilesystems`: 是否包含 `tmpfs/proc` 等伪文件系统
- `monitorCpu` / `monitorMemory` / `monitorDisk`: 是否真正监控对应指标（采集/趋势/告警）
- `showCpuInStatusBar` / `showMemoryInStatusBar` / `showDiskInStatusBar`: 是否在状态栏显示对应指标
- `cpuWarningPercent` / `cpuCriticalPercent`
- `memoryWarningPercent` / `memoryCriticalPercent`
- `diskWarningPercent` / `diskCriticalPercent`
- `enableNotifications`: 是否弹 VS Code 通知
- `notifyCooldownSeconds`: 告警通知冷却时间

示例：

```json
{
  "remoteResourceMonitor.diskMountPoints": [
    "/System/Volumes/Data",
    "/Volumes/WD_BLACK"
  ],
  "remoteResourceMonitor.diskAliases": {
    "/System/Volumes/Data": "data",
    "/Volumes/WD_BLACK": "repo"
  },
  "remoteResourceMonitor.diskDisplayMode": "remaining"
}
```

## 当前限制

- Windows 远程主机未做专门适配（会使用基础 Node 指标，磁盘可能不可用）。

## License

MIT
