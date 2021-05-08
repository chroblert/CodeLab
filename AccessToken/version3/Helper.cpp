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
	-p <pid>: �г�ĳ�������е�����
	-P <procName>: �г�ĳ�����̵�����
	-u <username>: �г�ĳ���û�������
	-v : ��ϸģʽ

[MODULE]	
	Execute
[OPTION]
	-p <pid>: �г�ĳ�������е�����
	-u <username>: ��ĳ���û�ִ�������-e <command>���ʹ��
	-e <command> : ִ������
	-c: �Ƿ��ڵ�ǰ�ն���ִ��
	-v : ��ϸģʽ)";
	printf("%s\n\n",rawUsageMsg);
}