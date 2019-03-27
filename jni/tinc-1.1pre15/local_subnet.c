#include "system.h"

#include "splay_tree.h"
#include "local_subnet.h"
#include "tinc_call.h"

#include <pthread.h>
#include <stdlib.h>

pthread_mutex_t tree_lock;
int local_subnet_lock_inited = 0;

splay_tree_t *local_subnet_tree;

static int my_maskcmp(const void *va, const void *vb, int masklen) {
	int i, m, result;
	const char *a = va;
	const char *b = vb;

	for(m = masklen, i = 0; m >= 8; m -= 8, i++) {
		result = a[i] - b[i];
		if(result)
			return result;
	}

	if(m)
		return (a[i] & (0x100 - (1 << (8 - m)))) -
			(b[i] & (0x100 - (1 << (8 - m))));

	return 0;
}

int local_subnet_compare(const local_subnet_t *a, const local_subnet_t *b)
{
	int result;

	result = b->net.prefixlength - a->net.prefixlength;

	if(result)
		return result;

	result = memcmp(&a->net.address, &b->net.address, sizeof(local_ipv4_t));

	return result;
}

local_subnet_t *new_local_subnet(void) {
	return calloc(1, sizeof(local_subnet_t));
}

void free_local_subnet(local_subnet_t *sn) {
	free(sn);
}

void init_local_subnet_tree()
{
	if (!local_subnet_lock_inited)
	{
		pthread_mutex_init(&tree_lock, NULL);
		local_subnet_lock_inited = 1;
	}
	local_subnet_tree = splay_alloc_tree((splay_compare_t) local_subnet_compare, (splay_action_t) free_local_subnet);
}

void local_subnet_tree_lock()
{
#if 1
	pthread_mutex_lock(&tree_lock);
#endif
	return;
}

void local_subnet_tree_unlock()
{
#if 1
	pthread_mutex_unlock(&tree_lock);
#endif
}

void free_local_subnet_tree()
{
	splay_delete_tree(local_subnet_tree);
	local_subnet_tree = NULL;
}

static void dump_local_subnet(local_subnet_t *sn)
{
	LOGD("+++++ dump local subnet: %u.%u.%u.%u/%u", 
	(unsigned int)sn->net.address.x[0],(unsigned int)sn->net.address.x[1],(unsigned int)sn->net.address.x[2], (unsigned int)sn->net.address.x[3], sn->net.prefixlength);
}

local_subnet_t* lookup_local_subnet_ipv4(const local_ipv4_t *address)
{
	local_subnet_t* r = NULL;
	for splay_each(local_subnet_t, p, local_subnet_tree) {
		//dump_local_subnet(p);
		if(!my_maskcmp(address, &p->net.address, p->net.prefixlength)) {
			r = p;
			break;
		}
	}
	return r;
}

local_subnet_t* local_subnet_add(local_ipv4_t *sn_ip, int prefixlength, local_ipv4_t *vip)
{
	local_subnet_t* r = new_local_subnet();
	memcpy(r->net.address.x, sn_ip->x, sizeof(sn_ip->x));
	r->net.prefixlength = prefixlength;
	splay_insert(local_subnet_tree, r);
	return r;
}

void local_subnet_del(local_subnet_t *del)
{
	splay_delete(local_subnet_tree, del);
}

void local_subnet_update_add(local_ipv4_t *sn_ip, int prefixlength, local_ipv4_t *vip)
{
	local_subnet_t* r = NULL;
	//LOGD("+++++ %s try 1", __FUNCTION__);
	r = lookup_local_subnet_ipv4(sn_ip);
	//LOGD("+++++ %s try 2", __FUNCTION__);
	if (!r)
	{
		r = local_subnet_add(sn_ip, prefixlength, vip);
	}
	//LOGD("+++++ %s try 3", __FUNCTION__);
	memcpy(r->vip.x, vip->x, sizeof(vip->x));
}

void local_subnet_update_del(local_ipv4_t *sn_ip)
{
	local_subnet_t* r = NULL;
	r = lookup_local_subnet_ipv4(sn_ip);
	if (r)
	{
		local_subnet_del(r);
	}
}

static int str2ipv4(char *ip, local_ipv4_t *sip)
{
	int ret = -1;
	unsigned int tmp1, tmp2, tmp3, tmp4;
	int scan_ret = sscanf(ip, "%u.%u.%u.%u", &tmp1, &tmp2, &tmp3, &tmp4);
	if (scan_ret == 4)
	{
		sip->x[0] = (uint8_t)tmp1;
		sip->x[1] = (uint8_t)tmp2;
		sip->x[2] = (uint8_t)tmp3;
		sip->x[3] = (uint8_t)tmp4;
		ret = 0;
	}
	return ret;
}

static int str2subnet(char* subnet, local_ipv4_t* sip, int* prefixlength)
{
	int ret = -1;
	char *ip_str = subnet;
	char *masklen_str = strchr(subnet, '/');
	if (masklen_str)
	{
		*masklen_str = 0;
		masklen_str++;
		ret = str2ipv4(ip_str, sip);
		*prefixlength = atoi(masklen_str);
	}
	return ret;
}

void local_subnet_str_add(char *subnet_str, char *vip_str)
{
	local_ipv4_t vip;
	local_ipv4_t sn_ip;
	//LOGD("+++++ local_subnet try add %s to %s", subnet_str, vip_str);
	int prefixlength;
	//LOGD("+++++ local_subnet try add 1");
	int subnet_ret = str2subnet(subnet_str, &sn_ip, &prefixlength);
	//LOGD("+++++ local_subnet try add 2");
	int vip_ret = str2ipv4(vip_str, &vip);
	//LOGD("+++++ local_subnet try add 3");
	if (subnet_ret == 0 && vip_ret == 0)
	{
		//LOGD("+++++ local_subnet try add 4");
		local_subnet_update_add(&sn_ip, prefixlength, &vip);
		//LOGD("+++++ local_subnet try add 5");
	}
}

void local_subnet_str_del(char *subnet_str)
{
	local_ipv4_t sn_ip;
	int prefixlength;
	int subnet_ret = str2subnet(subnet_str, &sn_ip, &prefixlength);
	if (subnet_ret == 0)
	{
		local_subnet_update_del(&sn_ip);
	}
}
