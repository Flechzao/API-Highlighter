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


## 作者

flechazo

## 贡献

欢迎提交拉取请求。对于重大更改，请先打开一个问题，讨论您想要更改的内容。

在适当的情况下，请确保更新测试。

## 许可证

[MIT](https://choosealicense.com/licenses/mit/)
