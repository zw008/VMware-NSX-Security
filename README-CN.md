# VMware NSX Security

> **作者**: Wei Zhou, VMware by Broadcom — wei-wz.zhou@broadcom.com
> 本项目由 VMware 工程师维护的社区项目，非 VMware 官方产品。
> VMware 官方开发者工具请访问 [developer.broadcom.com](https://developer.broadcom.com)。

VMware NSX DFW 微分段与安全管理 MCP skill — 20 个工具，涵盖分布式防火墙策略与规则、安全组、VM 标签、Traceflow 数据包追踪和 IDPS。

> **配套 skill**：[vmware-nsx](https://github.com/zw008/VMware-NSX)（网络）、[vmware-aiops](https://github.com/zw008/VMware-AIops)（VM 生命周期）、[vmware-monitor](https://github.com/zw008/VMware-Monitor)（监控）

## 快速开始

```bash
uv tool install vmware-nsx-security

mkdir -p ~/.vmware-nsx-security
cp config.example.yaml ~/.vmware-nsx-security/config.yaml
# 编辑 config.yaml，填写 NSX Manager 地址

echo "VMWARE_NSX_SECURITY_NSX_PROD_PASSWORD=your_password" > ~/.vmware-nsx-security/.env
chmod 600 ~/.vmware-nsx-security/.env

vmware-nsx-security doctor
```

## 功能

| 类别 | 工具数 |
|------|--------|
| DFW 策略 | 列出、获取、创建、更新、删除、列出规则（6 个） |
| DFW 规则 | 创建、更新、删除、统计（4 个） |
| 安全组 | 列出、获取、创建、删除（4 个） |
| VM 标签 | 列出标签、应用标签（2 个） |
| Traceflow | 运行追踪、获取结果（2 个） |
| IDPS | 列出 Profile、获取状态（2 个） |

**共 20 个 MCP 工具**（10 只读 + 10 写入）

## MCP 服务器配置

添加到 `~/.claude.json`：

```json
{
  "mcpServers": {
    "vmware-nsx-security": {
      "command": "vmware-nsx-security-mcp",
      "env": {
        "VMWARE_NSX_SECURITY_CONFIG": "~/.vmware-nsx-security/config.yaml"
      }
    }
  }
}
```

## 常见操作

### 对应用进行微分段

```bash
# 1. 按标签创建安全组
vmware-nsx-security group create web-vms --name "Web VMs" --tag-scope tier --tag-value web
vmware-nsx-security group create app-vms --name "App VMs" --tag-scope tier --tag-value app

# 2. 创建 DFW 策略
vmware-nsx-security policy create web-app-policy --name "Web to App" --category Application
```

### 为 VM 打标签

```bash
# 查询 VM 及其 external ID
vmware-nsx-security tag list my-vm-01

# 使用 external ID 应用标签
vmware-nsx-security tag apply <external-id> --scope tier --value web
```

### 追踪数据包路径

```bash
vmware-nsx-security traceflow run <src-lport-id> \
  --src-ip 10.0.1.5 --dst-ip 10.0.2.10 --proto TCP --dst-port 443
```

## 安全性

- **依赖检查**：有活跃规则时不允许删除策略；被 DFW 规则引用的安全组不允许删除
- **审计日志**：所有写操作记录到 `~/.vmware-nsx-security/audit.log`（JSON Lines 格式）
- **输入验证**：ID 字符集校验；API 返回文本经过 `_sanitize()` 清洗，防止提示注入
- **Dry-run 模式**：CLI 写命令均支持 `--dry-run` 预览
- **凭据安全**：密码仅从环境变量读取，永不写入 config.yaml

### 配套 Skill

| Skill | 功能范围 | 工具数 | 安装 |
|-------|---------|:-----:|------|
| **[vmware-aiops](https://github.com/zw008/VMware-AIops)** ⭐ 入口 | VM 生命周期、部署、Guest 操作、集群管理 | 31 | `uv tool install vmware-aiops` |
| **[vmware-monitor](https://github.com/zw008/VMware-Monitor)** | 只读监控：告警、事件、VM 信息 | 8 | `uv tool install vmware-monitor` |
| **[vmware-nsx](https://github.com/zw008/VMware-NSX)** | NSX 网络：Segment、网关、NAT、IPAM | 31 | `uv tool install vmware-nsx-mgmt` |
| **[vmware-storage](https://github.com/zw008/VMware-Storage)** | 数据存储、iSCSI、vSAN | 11 | `uv tool install vmware-storage` |
| **[vmware-vks](https://github.com/zw008/VMware-VKS)** | Tanzu 命名空间、TKC 集群生命周期 | 20 | `uv tool install vmware-vks` |
| **[vmware-aria](https://github.com/zw008/VMware-Aria)** | Aria Ops 指标、告警、容量规划 | 18 | `uv tool install vmware-aria` |

## 许可证

MIT
