# CodeLab
实验代码

## AccessToken

目前有如下功能：

- 列出所有进程中的主令牌
- 列出某个进程的主令牌及其线程中的模拟令牌
- 列出所有具有模拟令牌的线程
- 列出当前计算机上的登录会话
- 列出当前进程主令牌信息

待优化:

- 使用微软未公开函数ZwQueryInformationThread查看某些线程的时候，GetLastError()会返回“Access Denied"
- 将登录会话、访问令牌、线程、进程进行关联

用法：


![image](https://user-images.githubusercontent.com/24365224/113485987-00fd0100-94e3-11eb-868d-2af724031664.png)
