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
- **方法一**：选中 API 并单击 "切换测试状态" 按钮。
![ae0b952da5d202b43f3583875dd7c26](https://github.com/user-attachments/assets/abd78026-168e-43d6-90c5-dc2a909cf21d)
- **方法二**：在Proxy - HTTP history 界面中选中被标记的接口，右键选中Exrensions-API Highlighter -修改测试状态
6. 删除功能：要删除API，请在表格中选择它，然后单击“删除API”按钮。（支持多选）
  ![039d454a57720861509847c383c8f73](https://github.com/user-attachments/assets/c54222d9-ab73-44d9-8fe5-3559caf18934)

7. 置顶功能：若要将所有已测试的 API 移动到列表顶部，单击 "将已测试移至顶部" 按钮。
![117d232cc5e19ac42a84c3ac529cfac](https://github.com/user-attachments/assets/5adc8aee-5bda-4ebc-8590-50bd2eb58979)
单击后已测试的接口会置顶
![d409e0632942ea7a8c3b97ec83d4da4](https://github.com/user-attachments/assets/70b4dd49-ab1f-4362-b1d8-02a84c9b62c1)
8. 查找功能：若要查找特定的API，可以在搜索框中输入相关的API，然后点击"Find API"按钮。它将在表格中查找和高亮显示匹配搜索文本的API。
![335c0b036934dddf825decc85691a3d](https://github.com/user-attachments/assets/f5a5b5f2-63b9-45f4-930f-74fe999b554e)
9. 检查历史接口信息：勾选后，就会遍历当前HTTP history的接口信息，如果命中会打上历史接口检查的备注。
![513e241e61ffa5ad9ce52e73c973680](https://github.com/user-attachments/assets/6258371a-fd08-4ea9-93bd-a1053948955d)

检查结果如下：
![7d53caa6b69470eb98f62fa624ce71b](https://github.com/user-attachments/assets/ac277aac-e9b9-4100-ba14-5213bc0a2bd3)

10. 精确匹配功能：当启用精确匹配时，只有完全匹配的 URL 才会被高亮显示。禁用精确匹配时，只要包含相应 API 的 URL 都会被高亮显示。使用精确匹配功能可以方便地定位到特定的 API 以进行更有针对性的测试。
11. 检查完整数据包功能：如果需要检查整个HTTP请求（包括headers和body）是否包含API，可以勾选"检查完整数据包"选项，插件将在整个请求中查找API，不仅仅是URL。
12. 正则功能：可以使用正则表达式查找API，主要是处理特定模式的API。例如当API中包含通配符{id}、{databaseid}，可以使用正则表达式来匹配这些API。
13. URL编码功能：启用此选项后，插件就会从在编码的URL中查找API。（若要开启，可以在utils.py文件开启URL_encode函数）

### 普通示例 
大部分接口需求只涉及这部分，因此只需要了解这部分就行
1.例如我们想检查“/admission_pku/register.php”这个接口，导入到API表格中（无需勾选任意选项）
![2d72ddbc0c0b851ceeda42718dad98c](https://github.com/user-attachments/assets/9c292806-82d1-454a-a16c-b7ab43624802)

2.正常测试抓取流量，如果探测到接口就会标黄，如下图所示：
![edcd3ed572cddc20254e3529579e446](https://github.com/user-attachments/assets/786a4ac0-7309-4e15-9fcd-cdb567abff47)

## 版本更新记录

### v1.0.0
- 初始版本发布。

### v2.0.0
#### 新增功能
- **新增正则检查功能**
- **新增URL编码功能**
- **新增API 历史记录功能**
- **新增API 历史记录功能**

### v3.0.0
#### 新增功能
- **补充URL编码:** 增加了对更多URL编码的支持，现在支持除了字母、数字以为的特殊字符的URL编码。
- **补充正则检查规则:** 增加了更多正则检查规则，现在支持{XXXX}均可以识别为\d+，并提高了正则匹配的准确性。
- **漏洞数据增加:** 添加了对越权、未授权、普通等漏洞类型的支持。
- **自动补充HTTP Method:** 当接口信息不完整时，自动补充HTTP方法。
- **自动添加scope信息:** 捕获接口信息后，支持从接口列表点击直接跳转到HTTP历史记录中的对应接口。
- **URL模糊匹配:** 增加了URL模糊匹配功能，改进了接口匹配逻辑，支持接口名称不区分大小写。
- **新增敏感信息检查:** 增加了对HaE规则的支持，自动识别流量中的敏感信息。

#### 修复的bug
- **检查API历史时的性能问题:** 修复了使用“检查API历史记录”时该功能卡死的问题，通过添加多线程支持，提升了性能。
- **正则接口标记问题:** 修复了正则处理后部分接口不能识别的问题。
- **API表格问题:** 修复了中文输入报错问题。
- **URL编码和正则编码冲突:** 修复了同时启用URL编码和正则编码时，将\d+编码处理掉的问题，添加保护模式去防护。
- **domain被覆盖:** 修复了记录的接口域名被覆盖的问题。
  
### v3.1.0
#### 新增功能
- **新增未授权检查:** 增加对未授权漏洞的巡检。
  
#### 已知问题
- **添加scope在最新的burpsuite场景下不能使用:** 添加scope在最新的burpsuite场景下不能使用。

## 作者

flechazo

## 贡献

欢迎提交拉取请求。对于重大更改，请先打开一个问题，讨论您想要更改的内容。

在适当的情况下，请确保更新测试。

## 许可证

[MIT](https://choosealicense.com/licenses/mit/)
