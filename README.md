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

安装插件后，您可以按照以下步骤使用它：

1. 在Burp Suite中，选择"API-Highlighter"标签。
2. 要导入API，将它们粘贴到"Batch import APls"文本区域中，然后单击"Import APIs"按钮。
3. 导入的API将显示在下方的表格中。您可以为每个API添加注释和设置测试状态，若要标记 API 为已测试，请选中 API 并单击 "Toggle Tested" 按钮。已测试的 API 将被标记为绿色，未测试的 API 将被标记为黄色。。
4. 要删除API，请在表格中选择它，然后单击“Remove API”按钮。
5. 当拦截或查看请求时，插件会将包含指定API的请求以绿色（已测试）或黄色（未测试）高亮显示，并显示注释。
6. 若要将所有已测试的 API 移动到列表顶部，单击 "Move Tested to Top" 按钮。
7. 勾选 "Enable Precise Match" 选项可启用精确匹配功能。当启用精确匹配时，只有完全匹配的 URL 才会被高亮显示。禁用精确匹配时，只要包含相应 API 的 URL 都会被高亮显示。使用精确匹配功能可以方便地定位到特定的 API 以进行更有针对性的测试。

## 单词解释

Batch import APIs：api文本框

Import APIs：批量导入api

Enable Precise Match：开启精确匹配

Remove API：删除api

Toggle Tested：改变测试状态

Move Tested to Top：将已测试的api置顶

Find API：查找api

## 示例

目标接口：GET /api/query/identity/detail
导入接口
<img width="1635" alt="image" src="https://github.com/Flechzao/API-Highlighter/assets/66863063/90523a1b-ffa7-440a-a942-763d9b85707e">

查看高亮情况
<img width="1473" alt="image" src="https://github.com/Flechzao/API-Highlighter/assets/66863063/7fc9486b-7a9a-4644-a6a5-a5270fd7b5d4">

修改测试情况和备注
<img width="1474" alt="image" src="https://github.com/Flechzao/API-Highlighter/assets/66863063/858e29b8-ee7d-4be4-95a0-01a4ed005aec">

再次查看高亮情况
<img width="1466" alt="image" src="https://github.com/Flechzao/API-Highlighter/assets/66863063/01d5cda8-d2f1-49aa-8c38-428f8f875352">

## 特点

以下是此插件提供的一些关键功能：

- 为每个API添加注释和设置测试状态
- 将包含指定API的请求以绿色（已测试）或黄色（未测试）高亮显示

## 迭代情况 

|功能/缺陷修复|需求分析|功能设计实现|进度|期望版本|
|-|-|-|-|-|
|批量移除|无法删除|添加一个"remove apis"按钮，单击可删除，并添加批量选中功能|success|v1.1|
|快速改变测试状需要|快速改变测试状态，不需要像V1.0时的手动修改测试状态|添加一个"Toggle Tested"按钮，单击改变测试状态|success|v1.1|
|已测试选项置顶|更加直观|添加"Move Tested to Top"按钮，可以置顶当前已测试的API接口|success|v1.1|
|搜索框|大量接口测试的时候看不到|新增一个“find api”搜索框|success|v1.2|
|fix：搜索后能自动跳转对应的api|||success|v1.3|
|fix：修改测试状态后备注仍然未变更|||success|v1.3|
|fix：直接勾选test列，更改测试状态||功能实现失败，后续参考autorize的实现方式|developing|v1.3|
|备注同步|修改history时候，插件页的备注也会直接改变||failed|v 1.4|
|导出csv|可以导出测试记录|想调用logger中的“exprot as csv”功能|failed|V2|
|精确匹配/模糊查询|部分接口信息只有一个特定函数，因此需要设计一个功能来覆盖这种情况|当前版本可以实现一定的模糊查询，需要进一步优化。需要设计一个按钮，“是否开启精准匹配”，开启按钮后，当匹配host头和api完全符合才会标记|success|V2|

## 作者

flechazo

## 贡献

欢迎提交拉取请求。对于重大更改，请先打开一个问题，讨论您想要更改的内容。

在适当的情况下，请确保更新测试。

## 许可证

[MIT](https://choosealicense.com/licenses/mit/)
