# Pre-Release
|已完成✅|正在做的▶️|计划📌|
|-----|-----|-----|
|Database Lua API|更多Menu Lua API|Lua市场|
|Scan Lua API|Proxy Lua API|TeamServer|
|迁移到Tauri 2.0 Stable|Poc管理器||
|Nuclei支持|Lua配置管理器||
|Scan支持|||
|Summary支持|||
|i18n|||

# Fofa-GUI
来自Kanade-Project的第一个组件，通过Tauri构建的跨平台Fofa图形化工具。自v0.0.5版本开始支持附加Lua脚本并逐步重构为Kanade。

## Lua API
https://earlysun.gitbook.io/kanade-lua-api

#### 脚本路径
`~/.kanade/scripts/`
#### 优势
* 事件驱动|异步任务
* POC|Lua联动
* 跨平台
* Rust函数绑定
* LuaJIT/FFI提供的高效运行和C语言执行
* 简单、易用、全面的图形化接口组件

## 此仓库仅分发二进制程序，不发布源码。
## 如何使用？

#### 应用已损坏(MacOS)

应用没有签名导致，终端运行以下命令再次打开即可。
`xattr -cr /Applications/Kanade-FOFA.app`

#### 在设置中填入FOFA API Key即可使用
所有的设置项是自动保存在系统中的。
<img width="1476" alt="image" src="https://github.com/earlysun030201/Fofa-GUI/blob/main/images/iShot_2024-09-02_18.20.54.png">

<img width="1962" alt="image" src="https://github.com/user-attachments/assets/bdef076c-eead-4faf-848b-de9c03b7c4b0">


#### 查询字段

即返回结果中显示的字段内容。
所有API支持字段均开放选择。

#### 结果去重

根据ip-port进行结果重复项筛选并去除。

#### 静默存活检测

多线程扫描器，在结果返回并处理后进行ip-port扫描，目前仅支持ipv4地址扫描。

#### 语法

语法请参考fofa.info。


#### 导出数据

导出当前选中页的数据。

## 为什么要做这个？

计划做一个一体化的渗透测试工具，Fofa-GUI只是第一个组件，将来会在一体化工具内添加联动（存活检测、POC验证等）功能。

## 构建状态
✅:通过
❌:未通过
⏸️:已通过但未经验证/Github Actions等待
| 版本  | MacOS | Windows | Linux |
| ----- | ----- | ------- | ----- |
| 0.0.1 |✅|✅|❌|
| 0.0.2(pre-release)|✅|✅|✅|
| 0.0.3|✅|✅|✅|
| 0.0.4|✅|✅|✅|
| 0.0.5|✅|⏸️|⏸️|
| 0.0.6(pre-release)|✅|✅|✅|

## 开发状态
见截图
<img width="2480" height="1562" alt="SnowShot_2025-11-16_09-43-42" src="https://github.com/user-attachments/assets/bcfa5fd6-bff9-4d90-9b5d-52a5dcf93927" />
<img width="2480" height="1562" alt="SnowShot_2025-11-16_09-43-58" src="https://github.com/user-attachments/assets/2a0be471-4941-4797-b15c-68c99da1c6f3" />
<img width="2480" height="1562" alt="SnowShot_2025-11-16_09-44-15" src="https://github.com/user-attachments/assets/3249d70c-7973-4e62-83e0-10cde42b6bf3" />
<img width="2480" height="1562" alt="SnowShot_2025-11-16_09-44-31" src="https://github.com/user-attachments/assets/05998c3f-735a-4a21-84cc-964ef770f320" />
<img width="2480" height="1562" alt="SnowShot_2025-11-16_09-44-40" src="https://github.com/user-attachments/assets/df57b46f-ec04-479b-854e-a01b0f93802e" />
<img width="2480" height="1562" alt="SnowShot_2025-11-16_09-45-18" src="https://github.com/user-attachments/assets/312492a8-6847-4592-bc2e-7cdf8fc33278" />




## Star Chart
[![Stargazers over time](https://starchart.cc/earlysun030201/Fofa-GUI.svg?variant=adaptive)](https://starchart.cc/earlysun030201/Fofa-GUI)
