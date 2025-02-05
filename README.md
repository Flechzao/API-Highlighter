# API-Highlighter

This is a Burp Suite plugin for highlighting specific API requests and allowing users to batch import, remove APIs, as well as add comments and test statuses.

## 背景

最近公司调整了测试模式，需要根据接口表进行测试，如果常规的边测边看接口表太浪费时间了，故开发了这个插件，可以直接看到当前接口是否为目标接口，并实时标记功能点位置。

## 安装

要安装插件，请按照以下步骤操作：
1. 从本页面下载插件的最新版本。
2. 在Burp Suite中，导航到`Extender`标签。
3. 点击`Add`，然后选择下载的插件文件。
4. 此时插件应已安装并激活。
PS:需要正确配置jython环境才能使用此插件。

## 使用方法
### 基础功能
安装插件后，您可以按照以下步骤使用它：
1. 在Burp Suite中，选择"API-Highlighter"标签。
2. 要导入API，将它们粘贴到"批量导入API"文本区域中，然后单击"导入API"按钮。
![image](https://github.com/user-attachments/assets/47933745-7a8f-4ec9-bdb5-0d6ed875be53)
3. 导入的API将显示在下方的表格中。
4. 当拦截或查看请求时，插件会将包含指定API的请求以绿色（已测试）或黄色（未测试）高亮显示，并显示注释，标记为存在漏洞的API将被高亮显示为红色，并显示"Vulnerable"注释。
5. 设置测试状态，已测试的 API 将被标记为绿色，未测试的 API 将被标记为黄色。若要标记 API 为已测试，有如下两种方法：
   
  ○ 方法一：选中 API 并单击 "切换测试状态" 按钮。
  
  ○ 方法二：在Proxy - HTTP history 界面中选中被标记的接口，右键选中Exrensions-API Highlighter -修改测试状态
  
6. 删除功能：要删除API，请在表格中选择它，然后单击“删除API”按钮。（支持多选）
7. 置顶功能：若要将所有已测试的 API 移动到列表顶部，单击 "将已测试移至顶部" 按钮。
单击后已测试的接口会置顶
8. 查找功能：若要查找特定的API，可以在搜索框中输入相关的API，然后点击"Find API"按钮。它将在表格中查找和高亮显示匹配搜索文本的API。
9. 检查历史接口信息：勾选后，就会遍历当前HTTP history的接口信息，如果命中会打上历史接口检查的备注。
10. 精确匹配功能：当启用精确匹配时，只有完全匹配的 URL 才会被高亮显示。禁用精确匹配时，只要包含相应 API 的 URL 都会被高亮显示。使用精确匹配功能可以方便地定位到特定的 API 以进行更有针对性的测试。
11. 检查完整数据包功能：如果需要检查整个HTTP请求（包括headers和body）是否包含API，可以勾选"检查完整数据包"选项，插件将在整个请求中查找API，不仅仅是URL。
12. 正则功能：可以使用正则表达式查找API，主要是处理特定模式的API。例如当API中包含通配符{id}、{databaseid}，可以使用正则表达式来匹配这些API。
13. URL编码功能：启用此选项后，插件就会从在编码的URL中查找API。（若要开启，可以在utils.py文件开启URL_encode函数）

### 普通示例 
大部分接口需求只涉及这部分，因此只需要了解这部分就行
1.例如我们想检查“/admission_pku/register.php”这个接口，导入到API表格中（无需勾选任意选项）

2.正常测试抓取流量，如果探测到接口就会标黄，如下图所示：

## 版本更新记录


## 作者

flechazo

## 贡献

欢迎提交拉取请求。对于重大更改，请先打开一个问题，讨论您想要更改的内容。

在适当的情况下，请确保更新测试。

## 许可证

[MIT](https://choosealicense.com/licenses/mit/)
