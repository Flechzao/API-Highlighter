# API-Highlighter

This is a Burp Suite plugin for highlighting specific API requests and allowing users to batch import, remove APIs, as well as add comments and test statuses.

## 背景

最近公司需要调整了测试模式，需要根据接口表进行测试，如果常规的边测边看太浪费时间了，故开发了这个插件，可以边测边看当前接口是否为目标，并实时标记功能点位置。

## 安装

要安装插件，请按照以下步骤操作：
（需要正确配置jython才能使用此插件）
1. 从本页面下载插件的最新版本。
2. 在Burp Suite中，导航到`Extender`标签。
3. 点击`Add`，然后选择下载的插件文件。
4. 此时插件应已安装并激活。

## 使用方法

安装插件后，您可以按照以下步骤使用它：

1. 在Burp Suite中，导航到"API-Highlighter"标签。
2. 要导入API，请将它们粘贴到"Batch import APls"文本区域中，然后单击"Import APIs"按钮。
3. 导入的API将显示在下方的表格中。您可以为每个API添加注释和设置测试状态（Y/N）。
4. 要删除API，请在表格中选择它，然后单击“Remove API”按钮。
5. 当拦截或查看请求时，插件会将包含指定API的请求以绿色（已测试）或黄色（未测试）高亮显示，并显示注释。

## 特点

以下是此插件提供的一些关键功能：

- 为每个API添加注释和设置测试状态
- 将包含指定API的请求以绿色（已测试）或黄色（未测试）高亮显示

## 作者

pp

## 贡献

欢迎提交拉取请求。对于重大更改，请先打开一个问题，讨论您想要更改的内容。

在适当的情况下，请确保更新测试。

## 许可证

[MIT](https://choosealicense.com/licenses/mit/)
