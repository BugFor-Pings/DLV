<p align="center">
    <h1 align="center" >每日最新漏洞情报分享平台</h1>
    <p align="center">此项目是爬取多个漏洞平台构建漏洞预警，并将漏洞信息在平台进行展示</p>
        <p align="center">
    <a target="_blank" href="https://www.python.org/downloads/" title="Python version"><img src="https://img.shields.io/badge/python-%3E=_3.10-green.svg"></a>
    <a target="_blank" href="stars" title="stars"><img src="https://img.shields.io/github/stars/BugFor-Pings/bug_wiki.svg"></a>
    <a target="_blank" href="forks" title="forks"><img src="https://img.shields.io/github/forks/BugFor-Pings/bug_wiki.svg"></a>                                                 
</p>


欢迎来到 DLV(Daily Latest Vulnerabilities)每日最新漏洞情报分享仓库，本仓库是提供各平台每日最新的漏洞情报，帮助安全研究人员和系统管理员保护他们的系统免受潜在的威胁。

您可以在如下地址预览实时的漏洞情报：http://vul.hackersafe.cn（2025年底进行开源，就当送给各位的礼物了）

![图片](https://github.com/user-attachments/assets/7eddf641-1393-43a3-8c97-bb7a4450f8f0)


使用python+flask+sqllittle写的一个简易版本的平台搭建到公网供阅览各平台的最新漏洞情报

## 情报内容

每个漏洞情报包括以下详细信息：

- **漏洞标题：** 列出漏洞的标题，可以一眼看出是什么的漏洞（部分不展示）
- **漏洞编号：** CVE,CNVD等编号
- **披露时间：** 展示出漏洞披露的时间
- **漏洞详情：** 增加漏洞详情按钮，需要查看更多信息可点击按钮前往对应平台进行预览


## 使用方法

您可以通过以下方式使用这些漏洞情报：

1. **浏览漏洞情报：** 在本仓库文档中的平台查看当天各平台最新发布的漏洞情报。
2. **搜索漏洞情报：** 使用平台的搜索功能查找特定编号或标题关键词，以找到与您关注的漏洞相关的信息。


**目前平台每隔5分钟爬取下列5个平台数据进行展示！**

OSCS1024漏洞库，安天(antiycloud)，Tenable (Nessus)，Msrc(微软安全响应中心)CVE漏洞库 


## 免责声明

本仓库中的漏洞情报平台仅供信息共享和教育目的使用，不构成任何形式的法律建议或保证。使用本仓库中对应平台的信息时，请谨慎考虑并遵循适用的法律法规和最佳实践。

请注意：本仓库不对因使用或依赖于其中的信息而导致的任何损失或损害承担责任。


## 联系我们

如果您有任何问题、建议或需要帮助，请随时联系我们。您可以通过以下方式与我们联系：

- 在本仓库创建一个Issue
- 发送电子邮件至 [Pings@mps.ga]

感谢您的参与和支持！








