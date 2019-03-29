#include <stdio.h>
#include "net_tool.h"

void tool_ping_hosts(cJSON *hosts, int timeout)
{
	net_tool_ping_hosts(hosts, timeout);
}
