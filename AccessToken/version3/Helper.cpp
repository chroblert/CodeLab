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
	-p <pid|ALL>: �г����н����е����ƻ��г�ĳ�������е�����
	-t <tid|ALL>: �г������߳��е�ģ�����ƻ�ĳ���߳��е�ģ������
	-l : �г���ǰ���еĵ�¼�Ự
	-c : �г���ǰ����Ϣ
	-P : �Ƿ���ʾ�����е�privileges��Ϣ
	-u <username>: ��ĳ���û�ִ�������-e <command>���ʹ��
	-e <command> : ִ������
	-v : ��ϸģʽ)";
	printf("%s\n\n",rawUsageMsg);
}