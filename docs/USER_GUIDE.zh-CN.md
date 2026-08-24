# Process Memory Guard 使用说明

Process Memory Guard 是原生 macOS 菜单栏进程内存监视工具。它按应用分组组织进程规则，并为每条规则独立保存内存阈值、完整可执行路径和代码签名身份。

## 安装与运行

运行 `scripts/build.sh` 后，将 `outputs/Process Memory Guard.app` 复制到 `/Applications`。首次打开时允许通知；应用没有常驻 Dock 图标，从菜单栏内存芯片图标打开监视控制台。

## 规则与提醒

- 初始规则监视 Apple 的 `remotepairingd`，阈值为 1 GB。
- 可以创建应用分组，并从 `.app` 或具体可执行文件添加规则。
- 每条规则直接输入独立 GB 阈值。
- 告警通知支持输入 `1.5 GB`、`768 MB` 等值直接修改触发规则。
- 工具读取 `ri_phys_footprint`，不把虚拟地址空间当成实际内存。
- 工具不会自动结束任何进程。

## 可选 AI 二次分析

AI 默认关闭。配置后，API Key 仅保存到 macOS 钥匙串；只有规则首次越过阈值时，才会向已登记的 OpenAI Responses API 发送签名身份、阈值、采样间隔和最多 10 个内存样本。不会发送完整进程列表、文件、日志或设备标识。模型失败不影响本地阈值提醒。
