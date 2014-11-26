/*
 * yubo@xiaomi.com
 * 2014-08-21
 */
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#ifdef linux
#include <netinet/ether.h>
#endif

#include "trafficd.h"
#include "ip.h"
#include "hw.h"
#include "utils.h"
#include "system.h"
#include "ubus.h"

static struct avl_tree hws;
static struct trafficd_hw_data *hd;


static struct hw_node * hw_create_default(const char *hw);
static void hw_delete(struct hw_node *hw_node);
static void hw_node_cleanup(struct hw_node *hw_node);
static struct hw_node * hw_update(struct arp_entry *arp_entry);
static void hw_clean(void);

static struct hw_node * hw_create_default(const char *hwa)
{
	struct hw_node *hw_node;
	int ret;

	hw_clean();

	if(strlen(hwa) != 17){
		D(HW, "Create hw node '%s' failed, invalid name\n",  hwa);
		return NULL;
	}
	D(HW, "Create hw node '%s'\n",  hwa);
	hw_node = calloc(1, sizeof(*hw_node));
	if (!hw_node)
		return NULL;

	sys->hw_size++;

	INIT_LIST_HEAD(&hw_node->list);
	INIT_LIST_HEAD(&hw_node->ip_list);
	INIT_LIST_HEAD(&hw_node->child_list);
	hw_node->parent = NULL;

	if (hwa){
		strncpy(hw_node->hwa, hwa, HWAMAXLEN);
		strncpy(hw_node->log.hwa, hwa, HWAMAXLEN);
	}


	hw_node->avl.key = hw_node->hwa;
	ret = avl_insert(&hws, &hw_node->avl);
	if (ret < 0){
		free(hw_node);
		sys->hw_size--;
		return NULL;
	}
	hw_node->uptime = sys->uptime;
	hw_node->ageing_timer_value.tv_sec = 999;
	return hw_node;
}




struct hw_node * trafficd_hw_get(char *hwa, int create)
{
	struct hw_node *hw_node;

	//D(HW, "hw_get %s\n", hwa);
	hw_node = avl_find_element(&hws, hwa, hw_node, avl);
	if (hw_node) {
		return hw_node;
	}

	if (!create)
		return NULL;

	return hw_create_default(hwa);
}


static void hw_delete(struct hw_node *hw_node)
{
	if (!hw_node->avl.key)
		return;

	D(HW, "Delete hw node '%s'  from list\n",  hw_node->hwa);
	avl_delete(&hws, &hw_node->avl);
	hw_node->avl.key = NULL;

}

static void hw_node_cleanup(struct hw_node *hw_node)
{
	struct ip_node *ip_node, *tmp;
	D(HW, "Clean up hw '%s'  from list\n", hw_node->hwa);
	list_for_each_entry_safe(ip_node, tmp, &hw_node->ip_list, list){
		trafficd_ip_free(ip_node);
	}
	/*
	list_del(&hw_node->ip_list);
	*/
	hw_delete(hw_node);
}


void trafficd_hw_free(struct hw_node *hw_node)
{
	hw_node_cleanup(hw_node);
	free(hw_node);
	sys->hw_size--;
}

static time_t get_hw_lasttime(struct hw_node *hw_node){
	D(HW, "hw_node[0x%08x] hwa[%s] uptime[%lf] br_uptime[%ld] last_down_time[%ld]\n",
		hw_node, hw_node->hwa, hw_node->uptime, up2time(hw_node->br_uptime),
		hw_node->log.data[hw_node->log.index].down_time);
	if(hw_node->uptime)
		return up2time(hw_node->br_uptime);
	return hw_node->log.data[hw_node->log.index].down_time;
}

static int cmp_hw_node(const void *p1, const void *p2)
{
	D(HW, "p1 0x%08x 0x%08x p2 0x%08x 0x%08x\n", p1, *(void **)p1, p2, *(void **)p2);
	return get_hw_lasttime(*(struct hw_node **)p1)
			- get_hw_lasttime(*(struct hw_node **)p2);
}

#if 0
static void hw_sort_dubug(void)
{
	struct hw_node *hw_node, **hw_node_array;
	int i = 0;

	D(HW, "sys->hw_size[%d]\n", sys->hw_size);
	hw_node_array = calloc(sys->hw_size, sizeof(struct hw_node *));
	if(!hw_node_array){
		elog("calloc hw_node_array[%d] error\n", sys->hw_size);
		return;
	}

	i = 0;
	avl_for_each_element(&hws, hw_node, avl){
		D(HW, "%2d 0x%08x\n", i, hw_node);
		hw_node_array[i] = hw_node;
		i++;
	}

	qsort(&hw_node_array[0], sys->hw_size, sizeof(hw_node_array[0]), cmp_hw_node);

	for(i = 0; i < sys->hw_size; i++){
		D(HW, "no[%d], hwa[%s], lasttime[%s]\n",
			i, hw_node_array[i]->hwa,
			trafficd_ctime(get_hw_lasttime(hw_node_array[i])));
	}

	free(hw_node_array);
}
#endif

static void hw_log_create(struct hw_node *hw_node)
{
	struct timeval tv;
	struct hw_log_data *log_node;
	struct ip_node *ip_node;

	//get a log node
	hw_node->log.index = (hw_node->log.index + 1) % TRAFFICD_HW_LOGSIZE;
	log_node = &hw_node->log.data[hw_node->log.index];

	gettimeofday(&tv, NULL);
	log_node->up_time = tv.tv_sec + (time_t)(hw_node->uptime - sys->uptime);
	log_node->down_time = tv.tv_sec + (time_t)(hw_node->br_uptime - sys->uptime);
	log_node->rx_bytes = 0;
	log_node->tx_bytes = 0;
	list_for_each_entry(ip_node, &hw_node->ip_list, list){
		log_node->rx_bytes += ip_node->rx_bytes;
		log_node->tx_bytes += ip_node->tx_bytes;
	}

}

static void hw_reset_counter(struct hw_node *hw_node)
{
	struct ip_node *ip_node;

	if(hw_node->uptime)
		hw_log_create(hw_node);
	hw_node->uptime = sys->uptime;
	list_for_each_entry(ip_node, &hw_node->ip_list, list){
		ip_reset_counter(ip_node);
	}
}

static void hw_clean(void)
{
	struct hw_node *hw_node, **hw_node_array;
	int i = 0;

	if(sys->hw_size < sys->cfg.hw_sizelimit)
		return;

	hw_node_array = calloc(sys->hw_size, sizeof(struct hw_node *));
	if(!hw_node_array){
		elog("calloc hw_node_array[%d] error\n", sys->hw_size);
		return;
	}

	i = 0;
	avl_for_each_element(&hws, hw_node, avl){
		hw_node_array[i] = hw_node;
		i++;
	}

	qsort(&hw_node_array[0], sys->hw_size, sizeof(hw_node_array[0]), cmp_hw_node);

	for(i = 0; i < sys->cfg.hw_recycle; i++){
		trafficd_hw_free(hw_node_array[i]);
	}

	free(hw_node_array);
}

void trafficd_hw_update_ap(struct hw_node *hw_node, struct ip_node *ip_node)
{

	if (sys->uptime - hw_node->br_uptime > TRAFFICD_CLI_TIMEOUT2)
		hw_reset_counter(hw_node);

	if (ip_node->hw != hw_node){
		/*D(HW, "add ip %s to list hwa %s\n", arp_entry->ipa, hw_node->hwa);*/
		ip_node->hw = hw_node;
		_list_del(&ip_node->list);
		list_add_tail(&ip_node->list, &hw_node->ip_list);
	}
	hw_node->is_ap = 1;
	hw_node->br_seq = sys->bd->seq;
	hw_node->br_uptime = sys->bd->uptime;
	hw_node->ageing_timer_value.tv_sec = 0;
	if(!hw_node->uptime) hw_node->uptime = sys->bd->uptime;
	return;
}

void trafficd_hw_update_ap_sta(struct ip_node *speaker_ip, char *hw, char *ip)
{
	struct ip_node *ip_node;
	struct hw_node *hw_node;

	if(!speaker_ip->hw)
		return;

	if(!(hw_node = trafficd_hw_get(hw, true)))
		return;

	if (sys->uptime - hw_node->br_uptime > TRAFFICD_CLI_TIMEOUT2)
		hw_reset_counter(hw_node);

	if(hw_node->parent != speaker_ip->hw){
		hw_node->parent = speaker_ip->hw;
		_list_del(&hw_node->list);
		list_add_tail(&hw_node->list, &speaker_ip->hw->child_list);
	}

	/* skip ap, reported by itself */
	if(hw_node->is_ap)
		return;

	hw_node->br_seq = sys->bd->seq;
	hw_node->br_uptime = sys->bd->uptime;
	if(!hw_node->uptime) hw_node->uptime = sys->bd->uptime;

	if(!(ip_node = trafficd_ip_get(ip, true)))
		return;

	if (ip_node->hw != hw_node){
		/*D(HW, "add ip %s to list hwa %s\n", arp_entry->ipa, hw_node->hwa);*/
		ip_node->hw = hw_node;
		_list_del(&ip_node->list);
		list_add_tail(&ip_node->list, &hw_node->ip_list);
	}

	return;
}

static struct hw_node * hw_update(struct arp_entry *arp_entry)
{
	struct hw_node *hw_node;
	struct ip_node *ip_node;
	hw_node = trafficd_hw_get(arp_entry->hwa, true);
	if (hw_node && !hw_node->is_ap){
		/*D(HW, "hwa %s ip addr %s ip[%u.%u.%u.%u]\n", hw_node->hwa, arp_entry->ipa, HIPQUAD(arp_entry->ip));*/
		if((ip_node = _trafficd_ip_get(arp_entry->ip, true))){
			/*D(HW, "found ip_node %u.%u.%u.%u\n",  HIPQUAD(arp_entry->ip));*/
			if (ip_node->hw != hw_node){
				/*D(HW, "add ip %s to list hwa %s\n", arp_entry->ipa, hw_node->hwa);*/
				ip_node->hw = hw_node;
				_list_del(&ip_node->list);
				list_add_tail(&ip_node->list, &hw_node->ip_list);
			}
		}
	}
	return hw_node;
}



void trafficd_hw_update_assoclist()
{
	struct hw_node *hw_node;

	D(HW, "enter\n");
	avl_for_each_element(&hws, hw_node, avl) {
		hw_node->assoc = 0;
	}
	system_assoclist_update();
	sys->assoc_pending = false;
	D(HW, "leave\n");
}

void trafficd_hw_update_br(struct fdb_entry *f)
{
	/* like brctl */
	struct hw_node *hw_node;


	hw_node = trafficd_hw_get(f->hwa, true);
	if (hw_node){

		D(HW, "ifname[%s] agent[%ld]  hw_node[%s/%d] br[%d]\n",
			 f->ifname, f->ageing_timer_value.tv_sec,
			 hw_node->hwa, hw_node->br_seq, sys->bd->seq);


		if ((!hw_node->parent && sys->bd->seq - hw_node->br_seq > 1) ||
			(hw_node->parent && sys->uptime - hw_node->br_uptime > TRAFFICD_CLI_TIMEOUT2))
			hw_reset_counter(hw_node);


		if(!hw_node->parent ||
				sys->uptime - hw_node->br_uptime > TRAFFICD_CLI_TIMEOUT1){
			if (sys->bd->seq == hw_node->br_seq){
				/* for multi-bridge */
				if(hw_node->ageing_timer_value.tv_sec > f->ageing_timer_value.tv_sec){
					strncpy(hw_node->ifname, f->ifname, IFNAMSIZ);
					hw_node->ageing_timer_value.tv_sec = f->ageing_timer_value.tv_sec;
					hw_node->ageing_timer_value.tv_usec = f->ageing_timer_value.tv_usec;
	/*					hw_node->is_local = f->is_local;
					hw_node->br_seq = sys->bd->seq;
					hw_node->br_uptime = sys->bd->uptime;
					if(!hw_node->uptime) hw_node->uptime = sys->bd->uptime;*/
				}
			}else{
				strncpy(hw_node->ifname, f->ifname, IFNAMSIZ);
				hw_node->is_local = f->is_local;
				hw_node->ageing_timer_value.tv_sec = f->ageing_timer_value.tv_sec;
				hw_node->ageing_timer_value.tv_usec = f->ageing_timer_value.tv_usec;
				hw_node->br_seq = sys->bd->seq;
				hw_node->br_uptime = sys->bd->uptime;

				if(!hw_node->uptime)
					hw_node->uptime = sys->bd->uptime;

				if(hw_node->parent){
					hw_node->parent = NULL;
					_list_del(&hw_node->list);
					INIT_LIST_HEAD(&hw_node->list);
				}
			}
		}
	}
}

void trafficd_hw_iwevent(struct trafficd_iwevent *ev, struct hw_node *speaker)
{
	struct hw_node *hw_node;
	D(HW, "ifname[%s] hw[%s] assoc[%d]\n",
		ev->ifname, ev->hwa, ev->event_type);
	hw_node = trafficd_hw_get(ev->hwa, true);

	if(hw_node){
		if(ev->event_type == TRAFFICD_ASSOC_EVENT){
			hw_node->assoc = 1;
			if(speaker){
				strncpy(hw_node->ap_ifname, ev->ifname, IFNAMSIZ);
				if(hw_node->parent != speaker){
					/* maybe not necessary*/
					hw_node->parent = speaker;
					_list_del(&hw_node->list);
					list_add_tail(&hw_node->list, &speaker->child_list);
				}
			}else{
				strncpy(hw_node->ifname, ev->ifname, IFNAMSIZ);
			}

		}else if(ev->event_type == TRAFFICD_DISASSOC_EVENT){
			if(speaker){
				if(!strcmp(hw_node->ap_ifname, ev->ifname) &&
						hw_node->parent && hw_node->parent == speaker){
					hw_node->assoc = 0;
				}
			}else{
				if(!strcmp(hw_node->ifname, ev->ifname)){
					hw_node->assoc = 0;
				}
			}
		}
	}

	if(!sys->cfg.is_router){
		/* send event to router */
		blob_buf_init(&b1, 0);
		blobmsg_add_u32(&b1, "event", ev->event_type);
		blobmsg_add_string(&b1, "hw", ev->hwa);
		blobmsg_add_string(&b1, "ifname", ev->ifname);
		ubus_send_event(sys->tbus_ctx, sys->cfg.tbus_listen_event, b1.head);
	}
}




struct trafficd_hw_data * trafficd_hw_init()
{
	avl_init(&hws, avl_strcmp, false, NULL);

	hd = calloc(1, sizeof(* hd));
	if (!hd)
		return NULL;

	hd->seq = 0;
	hd->hws = &hws;

	return hd;
}


void trafficd_hw_done()
{
	struct hw_node *hw_node, *tmp;


	avl_for_each_element_safe(&hws, hw_node, avl, tmp)
		trafficd_hw_free(hw_node);

	if(hd)
		free(hd);
	hd = NULL;
}
