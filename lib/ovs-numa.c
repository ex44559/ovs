/*
 * Copyright (c) 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* On non-Linux, these functions are defined inline in ovs-numa.h. */
#ifdef __linux__

#include <config.h>
#include "ovs-numa.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include "hash.h"
#include "hmap.h"
#include "list.h"
#include "ovs-thread.h"
#include "openvswitch/vlog.h"
#include "connectivity.h"
#include "ovsdb-idl.h"
#include "vswitch-idl.h"
#include "ovsdb-data.h"
#include "dynamic-string.h"


VLOG_DEFINE_THIS_MODULE(ovs_numa);

/* ovs-numa module
 * ===============
 *
 * This module stores the affinity information of numa nodes and cpu cores.
 * It also provides functions to bookkeep the pin of threads on cpu cores.
 *
 * It is assumed that the numa node ids and cpu core ids all start from 0 and
 * range continuously.  So, for example, if 'ovs_numa_get_n_cores()' returns N,
 * user can assume core ids from 0 to N-1 are all valid and there is a
 * 'struct cpu_core' for each id.
 *
 * NOTE, this module should only be used by the main thread.
 *
 * NOTE, the assumption above will fail when cpu hotplug is used.  In that
 * case ovs-numa will not function correctly.  For now, add a TODO entry
 * for addressing it in the future.
 *
 * TODO: Fix ovs-numa when cpu hotplug is used.
 */

#define MAX_NUMA_NODES 128

/* numa node. */
struct numa_node {
    struct hmap_node hmap_node;     /* In the 'all_numa_nodes'. */
    struct ovs_list cores;          /* List of cpu cores on the numa node. */
    int numa_id;                    /* numa node id. */
};

/* Cpu core on a numa node. */
struct cpu_core {
    struct hmap_node hmap_node;/* In the 'all_cpu_cores'. */
    struct ovs_list list_node; /* In 'numa_node->cores' list. */
    struct numa_node *numa;    /* numa node containing the core. */
    unsigned core_id;          /* Core id. */
    bool available;            /* If the core can be pinned. */
    bool pinned;               /* If a thread has been pinned to the core. */
};

/* Contains all 'struct numa_node's. */
static struct hmap all_numa_nodes = HMAP_INITIALIZER(&all_numa_nodes);
/* Contains all 'struct cpu_core's. */
static struct hmap all_cpu_cores = HMAP_INITIALIZER(&all_cpu_cores);
/* True if numa node and core info are correctly extracted. */
static bool found_numa_and_core;

/* Returns true if 'str' contains all digits.  Returns false otherwise. */
static bool
contain_all_digits(const char *str)
{
    return str[strspn(str, "0123456789")] == '\0';
}

/* Discovers all numa nodes and the corresponding cpu cores.
 * Constructs the 'struct numa_node' and 'struct cpu_core'. */
static void
discover_numa_and_core(void)
{
    int n_cpus = 0;
    int i;

    for (i = 0; i < MAX_NUMA_NODES; i++) {
        DIR *dir;
        char* path;

        /* Constructs the path to node /sys/devices/system/nodeX. */
        path = xasprintf("/sys/devices/system/node/node%d", i);
        dir = opendir(path);

        /* Creates 'struct numa_node' if the 'dir' is non-null. */
        if (dir) {
            struct numa_node *n = xzalloc(sizeof *n);
            struct dirent *subdir;

            hmap_insert(&all_numa_nodes, &n->hmap_node, hash_int(i, 0));
            list_init(&n->cores);
            n->numa_id = i;

            while ((subdir = readdir(dir)) != NULL) {
                if (!strncmp(subdir->d_name, "cpu", 3)
                    && contain_all_digits(subdir->d_name + 3)){
                    struct cpu_core *c = xzalloc(sizeof *c);
                    unsigned core_id;

                    core_id = strtoul(subdir->d_name + 3, NULL, 10);
                    hmap_insert(&all_cpu_cores, &c->hmap_node,
                                hash_int(core_id, 0));
                    list_insert(&n->cores, &c->list_node);
                    c->core_id = core_id;
                    c->numa = n;
                    c->available = true;
                    n_cpus++;
                }
            }
            VLOG_INFO("Discovered %"PRIuSIZE" CPU cores on NUMA node %d",
                      list_size(&n->cores), n->numa_id);
            free(path);
            closedir(dir);
        } else {
            if (errno != ENOENT) {
                VLOG_WARN("opendir(%s) failed (%s)", path,
                          ovs_strerror(errno));
            }
            free(path);
            break;
        }
    }

    VLOG_INFO("Discovered %"PRIuSIZE" NUMA nodes and %d CPU cores",
               hmap_count(&all_numa_nodes), n_cpus);
    if (hmap_count(&all_numa_nodes) && hmap_count(&all_cpu_cores)) {
        found_numa_and_core = true;
    }
}

/* Gets 'struct cpu_core' by 'core_id'. */
static struct cpu_core*
get_core_by_core_id(unsigned core_id)
{
    struct cpu_core *core = NULL;

    if (ovs_numa_core_id_is_valid(core_id)) {
        core = CONTAINER_OF(hmap_first_with_hash(&all_cpu_cores,
                                                 hash_int(core_id, 0)),
                            struct cpu_core, hmap_node);
    }

    return core;
}

/* Gets 'struct numa_node' by 'numa_id'. */
static struct numa_node*
get_numa_by_numa_id(int numa_id)
{
    struct numa_node *numa = NULL;

    if (ovs_numa_numa_id_is_valid(numa_id)) {
        numa = CONTAINER_OF(hmap_first_with_hash(&all_numa_nodes,
                                                 hash_int(numa_id, 0)),
                            struct numa_node, hmap_node);
    }

    return numa;
}

/* Extracts the numa node and core info from the 'sysfs'. */
void
ovs_numa_init(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        discover_numa_and_core();
        ovsthread_once_done(&once);
    }
}

bool
ovs_numa_numa_id_is_valid(int numa_id)
{
    return found_numa_and_core && numa_id < ovs_numa_get_n_numas();
}

bool
ovs_numa_core_id_is_valid(unsigned core_id)
{
    return found_numa_and_core && core_id < ovs_numa_get_n_cores();
}

bool
ovs_numa_core_is_pinned(unsigned core_id)
{
    struct cpu_core *core = get_core_by_core_id(core_id);

    if (core) {
        return core->pinned;
    }

    return false;
}

/* Returns the number of numa nodes. */
int
ovs_numa_get_n_numas(void)
{
    return found_numa_and_core ? hmap_count(&all_numa_nodes)
                               : OVS_NUMA_UNSPEC;
}

/* Returns the number of cpu cores. */
int
ovs_numa_get_n_cores(void)
{
    return found_numa_and_core ? hmap_count(&all_cpu_cores)
                               : OVS_CORE_UNSPEC;
}

/* Given 'core_id', returns the corresponding numa node id.  Returns
 * OVS_NUMA_UNSPEC if 'core_id' is invalid. */
int
ovs_numa_get_numa_id(unsigned core_id)
{
    struct cpu_core *core = get_core_by_core_id(core_id);

    if (core) {
        return core->numa->numa_id;
    }

    return OVS_NUMA_UNSPEC;
}

/* Returns the number of cpu cores on numa node.  Returns OVS_CORE_UNSPEC
 * if 'numa_id' is invalid. */
int
ovs_numa_get_n_cores_on_numa(int numa_id)
{
    struct numa_node *numa = get_numa_by_numa_id(numa_id);

    if (numa) {
        return list_size(&numa->cores);
    }

    return OVS_CORE_UNSPEC;
}

/* Returns the number of cpu cores that are available and unpinned
 * on numa node.  Returns OVS_CORE_UNSPEC if 'numa_id' is invalid. */
int
ovs_numa_get_n_unpinned_cores_on_numa(int numa_id)
{
    struct numa_node *numa = get_numa_by_numa_id(numa_id);

    if (numa) {
        struct cpu_core *core;
        int count = 0;

        LIST_FOR_EACH(core, list_node, &numa->cores) {
            if (core->available && !core->pinned) {
                count++;
            }
        }
        return count;
    }

    return OVS_CORE_UNSPEC;
}

/* Given 'core_id', tries to pin that core.  Returns true, if succeeds.
 * False, if the core has already been pinned, or if it is invalid or
 * not available. */
bool
ovs_numa_try_pin_core_specific(unsigned core_id)
{
    struct cpu_core *core = get_core_by_core_id(core_id);

    if (core) {
        if (core->available && !core->pinned) {
            core->pinned = true;
            return true;
        }
    }

    return false;
}

/* Searches through all cores for an unpinned and available core.  Returns
 * the 'core_id' if found and sets the 'core->pinned' to true.  Otherwise,
 * returns OVS_CORE_UNSPEC. */
unsigned
ovs_numa_get_unpinned_core_any(void)
{
    struct cpu_core *core;

    HMAP_FOR_EACH(core, hmap_node, &all_cpu_cores) {
        if (core->available && !core->pinned) {
            core->pinned = true;
            return core->core_id;
        }
    }

    return OVS_CORE_UNSPEC;
}

/* Searches through all cores on numa node with 'numa_id' for an
 * unpinned and available core.  Returns the core_id if found and
 * sets the 'core->pinned' to true.  Otherwise, returns OVS_CORE_UNSPEC. */
unsigned
ovs_numa_get_unpinned_core_on_numa(int numa_id)
{
    struct numa_node *numa = get_numa_by_numa_id(numa_id);

    if (numa) {
        struct cpu_core *core;

        LIST_FOR_EACH(core, list_node, &numa->cores) {
            if (core->available && !core->pinned) {
                core->pinned = true;
                return core->core_id;
            }
        }
    }

    return OVS_CORE_UNSPEC;
}

/* Unpins the core with 'core_id'. */
void
ovs_numa_unpin_core(unsigned core_id)
{
    struct cpu_core *core = get_core_by_core_id(core_id);

    if (core) {
        core->pinned = false;
    }
}

/* Given the 'numa_id', returns dump of all cores on the numa node. */
struct ovs_numa_dump *
ovs_numa_dump_cores_on_numa(int numa_id)
{
    struct ovs_numa_dump *dump = NULL;
    struct numa_node *numa = get_numa_by_numa_id(numa_id);

    if (numa) {
        struct cpu_core *core;

        dump = xmalloc(sizeof *dump);
        list_init(&dump->dump);
        LIST_FOR_EACH(core, list_node, &numa->cores) {
            struct ovs_numa_info *info = xmalloc(sizeof *info);

            info->numa_id = numa->numa_id;
            info->core_id = core->core_id;
            list_insert(&dump->dump, &info->list_node);
        }
    }

    return dump;
}

void
ovs_numa_dump_destroy(struct ovs_numa_dump *dump)
{
    struct ovs_numa_info *iter;

    LIST_FOR_EACH_POP (iter, list_node, &dump->dump) {
        free(iter);
    }

    free(dump);
}

/* Reads the cpu mask configuration from 'cmask' and sets the
 * 'available' of corresponding cores.  For unspecified cores,
 * sets 'available' to false. */
void
ovs_numa_set_cpu_mask(const char *cmask)
{
    int core_id = 0;
    int i;

    if (!found_numa_and_core) {
        return;
    }

    /* If no mask specified, resets the 'available' to true for all cores. */
    if (!cmask) {
        struct cpu_core *core;

        HMAP_FOR_EACH(core, hmap_node, &all_cpu_cores) {
            core->available = true;
        }

        return;
    }

    for (i = strlen(cmask) - 1; i >= 0; i--) {
        char hex = toupper(cmask[i]);
        int bin, j;

        if (hex >= '0' && hex <= '9') {
            bin = hex - '0';
        } else if (hex >= 'A' && hex <= 'F') {
            bin = hex - 'A' + 10;
        } else {
            bin = 0;
            VLOG_WARN("Invalid cpu mask: %c", cmask[i]);
        }

        for (j = 0; j < 4; j++) {
            struct cpu_core *core;

            core = CONTAINER_OF(hmap_first_with_hash(&all_cpu_cores,
                                                     hash_int(core_id++, 0)),
                                struct cpu_core, hmap_node);
            core->available = (bin >> j) & 0x1;

            if (core_id >= hmap_count(&all_cpu_cores)) {
                return;
            }
	}
    }

    /* For unspecified cores, sets 'available' to false.  */
    while (core_id < hmap_count(&all_cpu_cores)) {
        struct cpu_core *core;

        core = CONTAINER_OF(hmap_first_with_hash(&all_cpu_cores,
                                                 hash_int(core_id++, 0)),
                            struct cpu_core, hmap_node);
        core->available = false;
    }
}

int 
discover_cpu_number_per_numa_node(void) 
{
	const char *path = "/sys/devices/system/node/node0/cpulist";
	int fd = open(path, O_RDONLY);
	char buffer[200];

	memset(buffer, 0, sizeof(buffer));
	if (read(fd, buffer, sizeof(buffer)) < 0) {
		VLOG_WARN("cannot read /sys/devices/system/node/node0/cpulist");
		return 1;
	}

	int cpu_count = 1; 
	for (int i = 0; i < sizeof(buffer); i++) {
		if (buffer[i] == ',') {
			cpu_count++;
		}
	}
	return cpu_count;
}

int64_t
discover_memory_per_numa_node(void) 
{
	const char *path = "/sys/devices/system/node/node0/meminfo";
	int fd = open(path, O_RDONLY);
	char buffer[800];

	memset(buffer, 0, sizeof(buffer));
	if (read(fd, buffer, sizeof(buffer)) < 0) {
		VLOG_WARN("cannot read /sys/devices/system/node/node0/meminfo");
		return 0;
	}

	int64_t memsize = 0;
	for (int i = 0; i < sizeof(buffer) && buffer[i] != 'k'; i++) {
		if (buffer[i] <= '9' && buffer[i] >= '0') {
			memsize = memsize * 10 + buffer[i] - '0';
		}
	}
	return memsize;
}

char *
discover_cpu_model(void)
{
	char *cpu_model = xzalloc(100 * sizeof(char));
	FILE *pp = popen("lscpu | grep \"Model name\"", "r");

	char buffer[200];
	memset(buffer, 0, sizeof(buffer));
	int j = 0;
	bool find = false;
	while (fgets(buffer, sizeof(buffer), pp) != NULL) {
		for (int i = 0; i < sizeof(buffer) && buffer[i] != '\0' && 
						buffer[i] != '\n'; i++) {
			if (buffer[i] == 'I') {
				find = true;
			}
			if (find) {
				cpu_model[j++] = buffer[i];
			}
		}
	}
	return cpu_model;
}

char *
discover_nic_dirver(char *nic_name) 
{
	char *cmd = xasprintf("ethtool -i %s | grep driver", nic_name);
	FILE *pp = popen(cmd, "r");

	char buffer[100];
	int j = 0;
	bool find = false, pre_find = false;
	char *nic_driver = xzalloc(100 * sizeof(char));
	memset(buffer, 0, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer), pp) != NULL) {
		for (int i = 0; i < sizeof(buffer) && buffer[i] != '\n'; i++) {
			if (buffer[i] == ':') {
				pre_find = true;
			}
			if (buffer[i] == 'i' && pre_find) {
				find = true;
			}
			if (find) {
				nic_driver[j++] = buffer[i];
			}
		}
	}
	free(cmd);
	return nic_driver;
}

char *
discover_nic_speed(char *nic_name) 
{
	int sock;
	struct ifreq ifr; /* this data structure defined in if.h */
	struct ethtool_cmd edata; /* this defined in ethtool.h */
	int rc;
	char *nic_speed = xzalloc(100 * sizeof(char));

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		VLOG_ERR("discover_nic_speed socket err\n");
		return nic_speed;
	}

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, nic_name);

	ifr.ifr_data = (char *)&edata;
	edata.cmd = ETHTOOL_GSET;
	/* get netdev speed info */
	rc = ioctl(sock, SIOCETHTOOL, &ifr);
	if (rc < 0) {
		VLOG_ERR("ofproto ioctl_ethtool aslb ioctl err\n");
		return nic_speed;
	}

	/* obtain netdevspeed. */
	switch(ethtool_cmd_speed(&edata)) {
		case SPEED_10:
			strcpy(nic_speed, "10");
			break;
		case SPEED_100:
			strcpy(nic_speed, "100");
			break;
		case SPEED_1000:
			strcpy(nic_speed, "1000");
			break;
		case SPEED_2500:
			strcpy(nic_speed, "2500");
			break;
		case SPEED_10000:
			strcpy(nic_speed, "10000");
			break;
		case SPEED_40000:
			strcpy(nic_speed, "40000");
			break;

		default:
			strcpy(nic_speed, "0");
	}

	close(sock);
	return nic_speed;
}

struct ovsdb_idl *idl;
unsigned int last_success_seqno, netdev_last_success_seqno;
unsigned int issued_config_last_success_seqno, data_report_last_success_seqno;

void 
ovs_numa_info_init(const char *remote) 
{	
	idl = ovsdb_idl_create(remote, &ovsrec_idl_class, false, true);
	last_success_seqno = ovsdb_idl_get_seqno(idl);
	ovsdb_idl_add_table(idl, &ovsrec_table_hardwareinfo);
	ovsdb_idl_add_column(idl, &ovsrec_hardwareinfo_col_NumaNodeNum);
	ovsdb_idl_set_lock(idl, "hardware_info");
	ovs_net_dev_init();
}

void 
ovs_net_dev_init(void) 
{	
	ovsdb_idl_add_table(idl, &ovsrec_table_port);
	ovsdb_idl_add_column(idl, &ovsrec_port_col_name);
}

void
ovs_numa_info_run(void) 
{
	ovsdb_idl_run(idl);
	
	if (!ovsdb_idl_has_lock(idl) || 
			ovsdb_idl_is_lock_contended(idl) || 
			!ovsdb_idl_has_ever_connected(idl)) {
			return;
	}

	unsigned int idl_seq = ovsdb_idl_get_seqno(idl);
	VLOG_INFO("IDL seqno is %d", idl_seq);
	if (idl_seq != last_success_seqno) {		
		const struct ovsrec_hardwareinfo *first_hardware_info;
		struct ovsrec_hardwareinfo *hardware_info;
		enum ovsdb_idl_txn_status status;
						
		first_hardware_info = ovsrec_hardwareinfo_first(idl);
		if (first_hardware_info) {
			VLOG_INFO("HardwareInfo already has a row.");
			idl_seq = last_success_seqno;
			return;
		} 
		struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(idl);
		hardware_info = ovsrec_hardwareinfo_insert(txn);
		VLOG_INFO("try to insert a row");

		int64_t numanodenum = hmap_count(&all_numa_nodes);
		int64_t CorePerNumaNode = ovs_numa_get_n_cores_on_numa(0);
		int64_t CPUPerNumaNode = discover_cpu_number_per_numa_node();
		int64_t MemoryPerNumaNode = discover_memory_per_numa_node();
		char *CPUType = discover_cpu_model();
		ovsrec_hardwareinfo_verify_NumaNodeNum(hardware_info);
		ovsrec_hardwareinfo_set_NumaNodeNum(hardware_info, numanodenum);
		ovsrec_hardwareinfo_set_CPUPerNumaNode(hardware_info, CPUPerNumaNode);
		ovsrec_hardwareinfo_set_CorePerNumaNode(hardware_info, CorePerNumaNode);
		ovsrec_hardwareinfo_set_MemoryPerNumaNode(hardware_info, MemoryPerNumaNode);
		ovsrec_hardwareinfo_set_CPUType(hardware_info, CPUType);

		
		status = ovsdb_idl_txn_commit_block(txn);
		VLOG_INFO("set hardware_info numa node number");
		
		if (status != TXN_INCOMPLETE) {	
			VLOG_INFO("txn is not incomplete.");
			ovsdb_idl_txn_destroy(txn);
			if (status == TXN_SUCCESS || status == TXN_UNCHANGED) {
				if (status == TXN_SUCCESS) {
					VLOG_INFO("txn success!");
					last_success_seqno = ovsdb_idl_get_seqno(idl);
					VLOG_INFO("New success IDL seqno is %d", idl_seq);
				}
			} else {
					VLOG_WARN("failed: set hardware_info numa node number.");
			   }
		}
		free(CPUType);
	}
	
}

void 
ovs_net_dev_run(void)
{
	ovsdb_idl_run(idl);

	if (!ovsdb_idl_has_lock(idl) || 
			ovsdb_idl_is_lock_contended(idl) || 
			!ovsdb_idl_has_ever_connected(idl)) {
			return;
	}
	
	unsigned int idl_seq = ovsdb_idl_get_seqno(idl);
	VLOG_INFO("netdev IDL seqno is %d", idl_seq);
	if (idl_seq != netdev_last_success_seqno) {
		const struct ovsrec_port *port;
		const struct ovsrec_netdevinfo *first_netdev_info;
		struct ovsrec_netdevinfo *netdev_info;
		enum ovsdb_idl_txn_status status;
						
		first_netdev_info = ovsrec_netdevinfo_first(idl);
		if (first_netdev_info) {
			VLOG_INFO("NetdevInfo already has a row.");
			return;
		} 
		
		for (port = ovsrec_port_first(idl); port != NULL; 
				port = ovsrec_port_next(port)) {
			if (strcmp(port->name, "ovsbr") == 0) {
				continue;
			}
			struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(idl);
			netdev_info = ovsrec_netdevinfo_insert(txn);
			VLOG_INFO("netdev: try to insert a row");

			char *driver = discover_nic_dirver(port->name);
			char *speed = discover_nic_speed(port->name);
			ovsrec_netdevinfo_set_Driver(netdev_info, driver);
			ovsrec_netdevinfo_set_Speed(netdev_info, speed);
			ovsrec_netdevinfo_set_ports(netdev_info, port->name);

			const char *Type = "Ethernet";
			bool IsUserSpace = false;
			int64_t NumaNode = 0;
			ovsrec_netdevinfo_set_NumaNode(netdev_info, NumaNode);
			ovsrec_netdevinfo_set_Type(netdev_info, Type);
			ovsrec_netdevinfo_set_IsUserSpace(netdev_info, IsUserSpace);

			status = ovsdb_idl_txn_commit_block(txn);
			VLOG_INFO("set netdev_info");
				
			if (status != TXN_INCOMPLETE) { 
				VLOG_INFO("netdev: txn is not incomplete.");
				ovsdb_idl_txn_destroy(txn);
				if (status == TXN_SUCCESS || status == TXN_UNCHANGED) {
					if (status == TXN_SUCCESS) {
						VLOG_INFO("netdev: txn success!");
						netdev_last_success_seqno = ovsdb_idl_get_seqno(idl);
						VLOG_INFO("netdev New success IDL seqno is %d", idl_seq);
					} else {
							VLOG_WARN("netdev failed: set netdev_info");
					}
				}
			}

			free(driver);
		}
		/*
		for (int i = 0; i < 4; i++) {


			
			const char *Driver;
			if (i == 0 || i == 1)
				Driver = "i40e";
			else
				Driver = "ixgbe";
			bool IsUserSpace = false;
			int64_t NumaNode = 0;
			const char *ports;
			if (i == 0)
				ports = "0754a7d8-484b-45d2-b648-874666f731e9";
			else if (i == 1)
				ports = "2a74fd6c-f00d-478b-b606-8affea411a93";
			else if (i == 2)
				ports = "3a914357-0720-485c-8637-4d352988ce13";
			else
				ports = "2c8c753f-796e-4c85-80a6-4039a5a7aef4";
			const char *Speed;
			if (i == 2 || i == 3) 
				Speed = "10000";
			else
				Speed = "40000";
			const char *Type = "Ethernet";
			ovsrec_netdevinfo_set_Driver(netdev_info, Driver);
			ovsrec_netdevinfo_set_IsUserSpace(netdev_info, IsUserSpace);
			ovsrec_netdevinfo_set_NumaNode(netdev_info, NumaNode);
			ovsrec_netdevinfo_set_ports(netdev_info, ports);
			ovsrec_netdevinfo_set_Speed(netdev_info, Speed);
			ovsrec_netdevinfo_set_Type(netdev_info, Type);
				

		}*/
	}
}

void 
ovs_issued_config_run(void)
{
	ovsdb_idl_run(idl);
		
	if (!ovsdb_idl_has_lock(idl) || 
			ovsdb_idl_is_lock_contended(idl) || 
			!ovsdb_idl_has_ever_connected(idl)) {
			return;
	}
	
	unsigned int idl_seq = ovsdb_idl_get_seqno(idl);
	VLOG_INFO("netdev IDL seqno is %d", idl_seq);
	if (idl_seq != issued_config_last_success_seqno) {
		const struct ovsrec_issuedconfig *first_issuedconfig;
		struct ovsrec_issuedconfig *issuedconfig_info;
		enum ovsdb_idl_txn_status status;
						
		first_issuedconfig = ovsrec_issuedconfig_first(idl);
		if (first_issuedconfig) {
			VLOG_INFO("issued config already has a row.");
			return;
		} 
		struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(idl);
		issuedconfig_info = ovsrec_issuedconfig_insert(txn);
		VLOG_INFO("issued config: try to insert a row");

		bool configChanged = true;
		bool isAlbMode = false;
		bool IsFallbackMode = true;
		bool IsUserConfigMode = false;
		int64_t ProcessToNode = 0;
		ovsrec_issuedconfig_set_configChanged(issuedconfig_info, configChanged);
		ovsrec_issuedconfig_set_isAlbMode(issuedconfig_info, isAlbMode);
		ovsrec_issuedconfig_set_IsFallbackMode(issuedconfig_info, IsFallbackMode);
		ovsrec_issuedconfig_set_IsUserConfigMode(issuedconfig_info, IsUserConfigMode);
		ovsrec_issuedconfig_set_ProcessToNode(issuedconfig_info, ProcessToNode);
				
		status = ovsdb_idl_txn_commit_block(txn);
		VLOG_INFO("set issued config");
				
		if (status != TXN_INCOMPLETE) { 
			VLOG_INFO("issued config: txn is not incomplete.");
			ovsdb_idl_txn_destroy(txn);
			if (status == TXN_SUCCESS || status == TXN_UNCHANGED) {
				if (status == TXN_SUCCESS) {
					VLOG_INFO("issued config: txn success!");
					issued_config_last_success_seqno = ovsdb_idl_get_seqno(idl);
					VLOG_INFO("issued config New success IDL seqno is %d", idl_seq);
				} else {
					VLOG_WARN("issued config failed: set netdev_info");
				}
			}
		}
	}
}

void 
ovs_data_report_run(void)
{
	ovsdb_idl_run(idl);
		
	if (!ovsdb_idl_has_lock(idl) || 
			ovsdb_idl_is_lock_contended(idl) || 
			!ovsdb_idl_has_ever_connected(idl)) {
			return;
	}
	
	unsigned int idl_seq = ovsdb_idl_get_seqno(idl);
	VLOG_INFO("data report IDL seqno is %d", idl_seq);
	if (idl_seq != data_report_last_success_seqno) {
		const struct ovsrec_datareport *first_dataReport;
		struct ovsrec_datareport *dataReport_info;
		enum ovsdb_idl_txn_status status;
						
		first_dataReport= ovsrec_datareport_first(idl);
		if (first_dataReport) {
			VLOG_INFO("data report already has a row.");
			return;
		} 
		struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(idl);
		dataReport_info = ovsrec_datareport_insert(txn);
		VLOG_INFO("data report: try to insert a row");

		bool ConfigError = true;
		bool isAlbMode = true;
		bool setProcessSuccess = false;
		const char *ErrorMessage = "CPU_ALLOC error";
		ovsrec_datareport_set_ConfigError(dataReport_info, ConfigError);
		ovsrec_datareport_set_isAlbMode(dataReport_info, isAlbMode);
		ovsrec_datareport_set_setProcessSuccess(dataReport_info, setProcessSuccess);
		ovsrec_datareport_set_ErrorMessage(dataReport_info, ErrorMessage);
				
		status = ovsdb_idl_txn_commit_block(txn);
		VLOG_INFO("set data report");
				
		if (status != TXN_INCOMPLETE) { 
			VLOG_INFO("data report: txn is not incomplete.");
			ovsdb_idl_txn_destroy(txn);
			if (status == TXN_SUCCESS || status == TXN_UNCHANGED) {
				if (status == TXN_SUCCESS) {
					VLOG_INFO("data report: txn success!");
					data_report_last_success_seqno = ovsdb_idl_get_seqno(idl);
					VLOG_INFO("data report New success IDL seqno is %d", idl_seq);
				} else {
					VLOG_WARN("data report failed: set netdev_info");
				}
			}
		}
	}
}

#endif /* __linux__ */
