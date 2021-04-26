#include "Helper.h"
#include <tchar.h>
#include <stdio.h>

void Helper::print_usage() {
	const char* rawUsageMsg = R"(
Usage: TokenUtil.exe <module> [OPTION]

[MODULE]
	ListTokens
	Execute

[OPTION]
	-p <pid|ALL>: 列出所有进程中的令牌或列出某个进程中的令牌
	-t <tid|ALL>: 列出所有线程中的模拟令牌或某个线程中的模拟令牌
	-l : 列出当前所有的登录会话
	-c : 列出当前的信息
	-P : 是否显示令牌中的privileges信息
	-u <username>: 以某个用户执行命令，与-e <command>结合使用
	-e <command> : 执行命令
	-v : 详细模式)";
	printf("%s\n\n",rawUsageMsg);
}