#include "system.h"

#include "control_common.h"
#include "hash.h"
#include "logger.h"
#include "net.h"
#include "netutl.h"
#include "node.h"
#include "splay_tree.h"
#include "utils.h"
#include "xalloc.h"

#include "peer_status.h"

void set_default_status(cJSON* peers)
{
	int i;
	int cnt = cJSON_GetArraySize(peers);
	for(i = 0; i < cnt; i++)
	{
		cJSON* item = cJSON_GetArrayItem(peers, i);
		cJSON* udp_confirmed_item = cJSON_GetObjectItem(item, "udp_confirmed");
		if (!udp_confirmed_item)
		{
			cJSON_AddNumberToObject(item, "udp_confirmed", 0);
		}
	}
	return;
}

void set_udp_confirmed(cJSON* peers, char *name)
{
	int i;
	int cnt = cJSON_GetArraySize(peers);
	for(i = 0; i < cnt; i++)
	{
		cJSON* item = cJSON_GetArrayItem(peers, i);
		cJSON* name_item = cJSON_GetObjectItem(item, "name");
		if (strcmp(name_item->valuestring, name) == 0)
		{
			cJSON_AddNumberToObject(item, "udp_confirmed", 1);
		}
	}
	return;
}

void dump_all_peers_status(cJSON *peers) {
	for splay_each(node_t, n, node_tree) {
		int udp_confirmed = 0;
		if (n->status.udp_confirmed)
		{
			set_udp_confirmed(peers, n->name);
		}
	}
	set_default_status(peers);
}
