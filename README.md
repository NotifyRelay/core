# @notify-relay/core

Notify-Relay 跨平台核心逻辑库。

## 目标

将 Android 和 PC 两端与原生平台无关的核心逻辑提取为 TypeScript，
编译为 UMD 格式，通过 JS 引擎（Android: QuickJS / PC: ClearScript）加载执行。

## 模块结构

```
src/
├── index.ts                  # 统一导出入口
├── types/                    # 类型定义层（纯接口/类型）
│   ├── protocol.ts           # 协议枚举/常量（DATA_* 头部、设备类型等）
│   ├── device.ts             # 设备/认证/心跳模型
│   ├── notification.ts       # 通知/超级岛/媒体播放模型
│   └── message.ts            # 协议消息模型 + 路由处理器类型
├── diff/                     # 差异负载层
│   ├── superisland.ts        # 超级岛 State/Diff 计算
│   ├── mediaplay.ts          # 媒体播放差异
│   ├── notification.ts       # 通用通知差异
│   └── store.ts              # 差异状态存储与合并
├── protocol/                 # 协议路由层
│   ├── router.ts             # DATA_* 报文解析与分发
│   ├── sender.ts             # 报文组装与发送队列
│   ├── constants.ts          # 头部常量与路由表
│   └── codec.ts              # 序列化/反序列化
├── notification/             # 通知处理层
│   ├── processor.ts          # 通知处理管线
│   └── filter.ts             # 过滤规则引擎
└── crypto/                   # 加密层
    ├── index.ts              # 接口导出
    ├── aes.ts                # AES-256-GCM
    ├── ecdh.ts               # ECDH 密钥协商
    └── hkdf.ts               # HKDF-SHA256 密钥派生
```

## 协议规范

### 报文格式

- 握手: `HANDSHAKE:<uuid>:<publicKey>:<ipAddress>:<batteryLevel>:<deviceType>`
- 接受: `ACCEPT:<uuid>:<publicKey>:<ipAddress>:<batteryLevel>:<deviceType>`
- 拒绝: `REJECT:<uuid>`
- 心跳TCP: `HEARTBEAT_TCP:<uuid>:<displayName>:<port>:<+/-><batteryLevel>:<deviceType>`
- 加密数据: `<DATA_HEADER>:<senderUuid>:<senderPubKey>:<encryptedPayload>`

### DATA_* 头部

| 头部 | 用途 |
|------|------|
| DATA_NOTIFICATION | 普通通知转发 |
| DATA_SUPERISLAND | 超级岛通知（全量/差异/结束） |
| DATA_MEDIAPLAY | 媒体播放通知 |
| DATA_ICON_REQUEST/RESPONSE | 图标同步 |
| DATA_APP_LIST_REQUEST/RESPONSE | 应用列表同步 |
| DATA_MEDIA_CONTROL | 媒体控制 |
| DATA_CLIPBOARD | 剪贴板同步 |
| DATA_FTP | FTP 服务启停 |
| DATA_STATUS | 状态响应（含超级岛 ACK） |
| DATA_APP_LAUNCH | 远程应用启动 |

### 加密

- 密钥交换: ECDH (secp256r1)
- 密钥派生: HKDF-SHA256
- 数据加密: AES-256-GCM (128bit tag)

## 构建

```bash
npm install
npm run build        # 输出 dist/core.umd.js + dist/core.esm.js
npm run test         # 运行测试
npm run typecheck    # 类型检查
```

## 集成

### Android (QuickJS)

```kotlin
// 1. 将 dist/core.umd.js 放入 assets/
// 2. 创建 QuickJS 运行时
val runtime = QuickJS.createRuntime()
val context = QuickJS.createContext(runtime)
// 3. 加载 JS
context.eval(readAssetFile("core.umd.js"))
// 4. 调用
context.eval("NotifyRelayCore.diff.superisland.computeFeatureId(...)")
```

### PC (ClearScript)

```csharp
using Microsoft.ClearScript.V8;
using Microsoft.ClearScript;

// 1. 加载 JS
using var engine = new V8ScriptEngine();
engine.Execute(File.ReadAllText("core.umd.js"));
// 2. 调用
var result = engine.Script.NotifyRelayCore.diff.superisland.computeFeatureId(...);
```
