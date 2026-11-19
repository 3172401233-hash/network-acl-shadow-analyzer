# network-acl-shadow-analyzer

IPv4/IPv6 访问控制列表（ACL）**静态配置分析器**，使用 Python 3.8.2 标准库实现。

它按配置顺序分析规则之间的流量空间交叉，报告：

- **完全遮蔽（fully shadowed）**：规则的全部匹配空间已被前置规则占用，永远不会命中。
- **部分遮蔽（partially shadowed）**：规则只有一部分还能命中，报告具体剩余流量。
- **冗余片段（redundant fragments）**：与前置规则动作相同的重叠部分，删除后不影响策略。
- **动作冲突（action conflicts）**：前置 `deny` 与后置 `allow`（或反之）在同一流量上冲突，
  由于按顺序匹配，前置动作生效，后置规则的该片段被覆盖。
- **规则重复（duplicate）**：与某条前置规则的匹配空间完全相同。

> 本工具只做静态配置分析，**不会生成、下发或执行任何防火墙命令**，也不会向任何设备发起连接。

## 为什么不能只比较规则文本

规则在以下维度上是集合而非字符串：

- 源 / 目的 CIDR（IPv4 与 IPv6 整数地址区间，支持跨网段包含与相邻合并）
- 协议（`tcp`、`udp`、`icmp`、数字协议号、`any`）
- 源 / 目的端口（单端口、`8000-9000` 区间、`80,443` 非连续端口、全端口）
- 连接状态标记（`new`、`established`、`related`、`invalid` 或自定义数字）

分析器把每条规则建模为多维“盒子（Box）”，对盒子做交集与差集运算，
因此能发现文本完全不同但网段 / 端口范围交叉的遮蔽关系。

## 优先级语义

- 规则严格按**配置顺序**处理，绝不按网段大小或前缀长度重新排序。
- 同一方向（`in` / `out`）内，前置规则先占用流量空间；后置规则只能拿到剩余空间。
- 不同方向的规则互不影响，分别分析。
- IPv4 与 IPv6 地址空间不相交，混合配置时只会在同协议族内部产生遮蔽。
- 空规则集返回空报告，不报错。

## 目录结构

```
acl_analyzer/
  model.py      规则模型与输入归一化、校验
  space.py      区间 / Box 几何运算、区间到 CIDR 的最小化转换、相邻合并
  analyzer.py   顺序遮蔽 / 冲突 / 冗余分析引擎
  parser.py     文本规则解析
  report.py     纯文本报告渲染
  __main__.py   命令行入口
tests/          unittest 测试（32 个用例）
examples/       示例规则文件
```

## 命令行用法

```bash
python -m acl_analyzer examples/rules.txt
# 或从标准输入读取
cat examples/rules.txt | python -m acl_analyzer -
```

文本规则格式（`#` 注释、空行允许）：

```
id 方向 动作 源CIDR -> 目的CIDR [协议] [目的端口] [源端口] [状态]
```

示例：

```
10 in deny 10.0.0.0/16 -> 0.0.0.0/0 tcp 80,443
20 in allow 10.0.1.0/24 -> 0.0.0.0/0 tcp 443
50 out allow 2001:db8::/32 -> ::/0 any any any new,established
```

- 动作接受 `allow/permit/accept/pass` 与 `deny/drop/block/reject`。
- 端口支持 `80`、`8000-9000`、`80,443,8080`、`any`。
- 协议支持名称、数字号与 `any`；状态支持名称、数字与逗号列表。

## Python API

```python
from acl_analyzer import Rule, analyze

rules = [
    Rule(rule_id="10", direction="in", action="deny",
         src_cidr="10.0.0.0/16", dst_cidr="0.0.0.0/0",
         protocol="tcp", dst_ports="80"),
    Rule(rule_id="20", direction="in", action="allow",
         src_cidr="10.0.1.0/24", dst_cidr="0.0.0.0/0",
         protocol="tcp", dst_ports="80"),
]

report = analyze(rules)
for item in report.analyses:
    print(item.rule.rule_id, item.status)
    for cause in item.shadowed_by:
        print("  遮蔽来源:", cause.rule_id, cause.action,
              "片段数:", len(cause.fragments))
    for text in item.remaining_fragments_text(
            report.protocol_names, report.state_names):
        print("  剩余流量:", text)
```

`RuleAnalysis` 的关键属性：

- `status`：`active` / `partially_shadowed` / `fully_shadowed`
- `shadowed_by`：每条前置遮蔽规则及其被覆盖的 Box 片段
- `effective_boxes`：该规则仍能命中的剩余流量空间
- `redundant_fragments` / `conflicts`：同动作冗余与异动作冲突
- `duplicate_of`：完全重复的前置规则 ID

## 实现要点

- 所有区间统一为半开整数区间 `[start, end)`，端口区间在渲染时转回闭区间显示。
- Box 差集沿“源 IP → 目的 IP → 协议 → 源端口 → 目的端口 → 状态”逐维切割，
  保证结果互不重叠且可完整还原剩余空间。
- IP 区间通过“取最大对齐块”算法转换为数量最少的 CIDR 列表。
- 相邻且其余维度完全相同的 IP 片段会反复合并，避免报告出现大量碎片。
- `protocol=any` / `states=any` 会展开为当前规则集出现过的协议 / 状态全集，
  因此“某协议具体规则 + any 规则”能正确计算部分遮蔽。

## 运行测试

```bash
python -m unittest
```

测试覆盖：完全与部分遮蔽、动作冲突、相邻网段合并、IPv4/IPv6 区间转 CIDR、
IPv6 归类、IPv4/IPv6 混合配置、规则重复、输入顺序敏感、协议不匹配、
非连续端口、全端口、状态标记、方向隔离、空规则集、输入校验与 CLI。

## 已知限制

- 端口分析基于 L4 端口；`icmp` 等无端口协议按全端口空间处理。
- 不解析真实厂商配置语法（iptables / nftables / 安全组 JSON 等），
  请先转换为 `Rule` 或本文的文本格式。
- 不做 NAT、路由可达性或有状态会话的动态判断，仅分析声明的匹配空间。
