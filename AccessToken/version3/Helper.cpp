#include "Helper.h"
#include <tchar.h>
#include <stdio.h>

void Helper::print_usage() {
	const char* rawBanner = R"(
===============TokenUtil================
|          author:JC0o0l               |
|          wechat:JC_SecNotes          |
|          version:1.0[2105]           |
========================================)";
	printf("%s\n\n", rawBanner);

	const char* rawUsageMsg = R"(
Usage: TokenUtil.exe <module> [OPTION]

[MODULE]
	ListTokens
[OPTION]
	-p <pid>: 列出某个进程中的令牌
	-P <procName>: 列出某个进程的令牌
	-u <username>: 列出某个用户的令牌
	-v : 详细模式

[MODULE]	
	Execute
[OPTION]
	-p <pid>: 列出某个进程中的令牌
	-u <username>: 以某个用户执行命令，与-e <command>结合使用
	-e <command> : 执行命令
	-c: 是否在当前终端下执行
	-v : 详细模式)";
	printf("%s\n\n",rawUsageMsg);
}