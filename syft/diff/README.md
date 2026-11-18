# SBOM 跨版本差异对比（`syft diff`）

`syft diff` 接收两份已经生成的 SBOM 快照，在内存中完成组件级差异计算，输出新增、
消失、版本变化三类结果，并提供面向流水线的机器可读报告与门禁退出码。整个过程不要求
用户把中间结果落盘再读回，也不引入新的第三方依赖。

## 快速开始

```bash
# 人类可读的分组表格
syft diff old.syft.json new.syft.json

# 机器可读 JSON 报告
syft diff old.syft.json new.syft.json --diff-format json

# 只看高风险变化（新引入组件 + 版本降级）
syft diff old.syft.json new.syft.json --high-risk

# 限定到某个子系统目录
syft diff old.syft.json new.syft.json --scope ./subsystem

# 组件数量很大时逐行流式输出（每行一个 JSON 对象）
syft diff old.syft.json new.syft.json --diff-format jsonl

# 分页输出
syft diff old.syft.json new.syft.json --page-size 500 --page 2

# 流水线门禁：出现高风险变化时以非零码退出
syft diff old.syft.json new.syft.json --diff-format json --fail-on high-risk

# 任意一侧支持从 STDIN 读取（最多一侧）
cat new.syft.json | syft diff old.syft.json -
```

## 组件同一性规则

组件匹配不能只按名称字符串比较（不同生态存在大量同名组件）。差异计算按以下确定性
顺序建立同一性：

1. **PURL 规则（主规则，`identityRule: "purl"`）**：解析组件的 Package URL，规范化后
   去掉 `version` 与 `subpath`，以剩余的 `type/namespace/name/qualifiers` 作为同一
   性键。版本天然不参与同一性判定；发行版限定词（如 `arch`、`distro`、
   `repository_url`）保留，因此同一名字但来自不同发行版的组件不会被误判为同一个。
2. **名称+类型降级规则（`identityRule: "name+type"`）**：组件缺少 PURL 或 PURL 无法
   解析时，使用「包生态类型 + 名称」匹配，结果一定带 `unreliable: true` 标记。
3. **名称兜底规则（`identityRule: "name"`）**：连包类型都缺失时仅按名称匹配，同样
   标记为不可靠。

注意：SBOM 内部的 `id` 是对组件全部属性做内容哈希得到的，版本一变就变，不能作为跨
版本同一性键，因此差异计算不使用它。

当同一性键下出现多个组件（同一键多版本/多位置）时，结果会被标记为 `unreliable`，
版本字段以逗号汇总，提醒人工复核。

## 差异类型与版本方向

| 类型 `type` | 含义 |
| --- | --- |
| `added` | 仅新清单存在的组件（默认计为高风险） |
| `removed` | 仅旧清单存在的组件 |
| `version-changed` | 两侧都存在但版本不同，`direction` 给出方向 |
| `version-unknown` | 任一侧缺失版本号，无法判断升级/降级；独立归类，绝不并入「无变化」 |

版本方向 `direction`：

| 方向 | 判定 |
| --- | --- |
| `upgrade` | 新版 semver 高于旧版，且主/次版本至少一个变化 |
| `downgrade` | 新版 semver 低于旧版（默认计为高风险） |
| `revision-only` | 主、次版本不变，仅修订号（patch）变化且新版更新 |
| `uncomparable` | 版本无法解析为 semver（如日期版本、自由文本），同时标记 `unreliable` |

版本解析依次尝试：原始字符串 → 去掉 epoch 前缀（`1:2.3.4`）→ 去掉前导 `v` →
提取首个点分数字段。单个裸整数（如 `20240101`）不会被当成 major 版本，避免日期版本
产生虚假的升级结论。

## 依赖层与分组

差异结果同时支持两种分组维度（JSON 报告的 `counts.byType`、`counts.byLayer`）：

- 按组件类型（`componentType`，如 `python`、`npm`、`apk`）。
- 按来源层：根据 SBOM 的 `dependency-of` 关系计算，没有任何依赖边指向的组件为
  `direct`（直接依赖），被其他组件依赖的为 `transitive`（传递依赖）；清单完全没有
  依赖关系时记为 `unknown`。

组件在直接/传递层之间移动时会产生一条 `version-changed` + `uncomparable` 的记录，
并以 `layerChanged: true` 与 `oldLayer`/`newLayer` 显式标注，传递依赖的变化因此可被
直接发现。

## 来源差异与审计字段

报告头部为两侧输入各保留一份来源描述：

- `path`、`format`、`schemaVersion`：输入位置与 SBOM 格式/schema。
- `sourceType`、`sourceName`、`sourceVersion`：被扫描对象的类型（`image`、
  `directory`、`file`）与名称、版本。
- `generatedAt`：清单生成时间，优先取文档内时间字段（syft descriptor、SPDX
  creationInfo、CycloneDX metadata），缺失时回退到输入文件的修改时间，都没有则为
  `null`。
- `componentCount`：路径范围过滤后参与对比的组件数。

当两侧来源类型不同（例如镜像 vs 目录），报告顶层 `sourceMismatch: true`，表格输出
同时打印 WARNING，提示位置路径不能直接对比。

## 机器可读报告字段

`--diff-format json` 输出单个 JSON 文档；`jsonl` 第一行为报告头（不含 changes），
之后每行一个 change 对象，适合几十万组件的流式消费。

顶层字段：

| 字段 | 说明 |
| --- | --- |
| `reportSchema` | 差异报告自身的结构版本 |
| `old` / `new` | 两侧输入的来源描述 |
| `sourceMismatch` | 两侧来源类型是否不同 |
| `pathScope` | 生效的路径前缀（未限定则省略） |
| `highRiskOnly` | 是否只输出高风险变化 |
| `counts` | 各类型、方向、组件类型、依赖层的计数 |
| `changes` | 当前页的变化条目 |
| `totalChanges` | 分页前的变化总数 |
| `page` / `pageSize` | 分页参数（`pageSize=0` 表示不分页） |

单条 change 字段：`type`、`direction`、`name`、`componentType`、`purl`、
`oldVersion`、`newVersion`、`identityKey`、`identityRule`、`unreliable`、`oldLayer`、
`newLayer`、`layerChanged`、`highRisk`、`paths`（位置带 `old=`/`new=` 前缀）。

## 流水线门禁用法

`--fail-on` 可重复指定，命中任意规则即返回非零退出码（报告仍然完整输出）：

| 规则 | 触发条件 |
| --- | --- |
| `added` | 存在新增组件 |
| `removed` | 存在消失组件 |
| `version-changed` | 存在版本变化 |
| `version-unknown` | 存在无法判定版本方向的变化 |
| `downgrade` | 存在版本降级 |
| `high-risk` | 存在高风险变化（新增或降级） |

无人值守示例（每周组件变化周报）：

```bash
#!/usr/bin/env bash
set -euo pipefail

syft diff baseline.syft.json current.syft.json \
  --diff-format jsonl \
  --fail-on high-risk \
  > weekly-component-diff.jsonl
```

消费方也可以直接读取 JSON 报告的 `counts.highRisk` 自行决策，而不依赖退出码。

## 失败与降级行为

- **schema 版本不一致**：两份输入的 `(format, schemaVersion)` 任一不同即拒绝对比，
  错误信息同时打印两侧版本，例如
  `refusing to diff SBOMs with different schema versions: old=syft-json/15.0.0 new=syft-json/16.1.13`。
- **解析失败**：错误带输入路径与具体位置（行、列、字节偏移），例如
  `SBOM parse failure for "x.json" at line 4 column 4 (byte offset 42): ...`；文件
  读取失败则标记为 `read` 阶段错误。
- **缺少唯一标识**：按名称+类型（最终按名称）降级匹配，并在每条结果上标注
  `unreliable: true` 与实际使用的 `identityRule`。
- **零组件清单**：正常输出完整差异结构（`changes` 为空数组、计数为 0），不会触发
  空指针。
- **无 diff 模式时零影响**：不调用 `syft diff` 时，现有 SBOM 生成、字段顺序、输出
  格式选项与既有测试的行为完全不变；本次改动没有修改任何现有生成路径。
