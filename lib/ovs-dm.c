#include <config.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "ovs-dm.h"
#include "openvswitch/vlog.h"
#include "util.h"
#include "ovsdb-idl.h"
#include "vswitch-idl.h"


VLOG_DEFINE_THIS_MODULE(ovs_dm);

char errorMsg[200];

void ovs_dm_set_alb_mode(struct ovsdb_idl *idl) {
	const struct ovsrec_port *port;
	enum ovsdb_idl_txn_status status;
	
	for (port = ovsrec_port_first(idl); port != NULL; 
		port = ovsrec_port_next(port)) {
		if (strcmp(port->name, "bond0") == 0) {
			struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(idl);
			ovsrec_port_set_bond_mode(port, "balance-aslb");

			status = ovsdb_idl_txn_commit_block(txn);
			VLOG_INFO("set bond0 balance-aslb");
				
			if (status != TXN_INCOMPLETE) { 
				VLOG_INFO("set bond0 balance-aslb: txn is not incomplete.");
				ovsdb_idl_txn_destroy(txn);
				if (status == TXN_SUCCESS || status == TXN_UNCHANGED) {
					if (status == TXN_SUCCESS) {
						VLOG_INFO("set bond0 balance-aslb: txn success!");
					} else {
							VLOG_WARN("set bond0 balance-aslb: failed");
					}
				}
			}
		}
	}
}

void ovs_dm_set_none_alb_mode(struct ovsdb_idl *idl) {
	const struct ovsrec_port *port;
	enum ovsdb_idl_txn_status status;
	
	for (port = ovsrec_port_first(idl); port != NULL; 
		port = ovsrec_port_next(port)) {
		if (strcmp(port->name, "bond0") == 0) {
			struct ovsdb_idl_txn *txn = ovsdb_idl_txn_create(idl);
			ovsrec_port_set_bond_mode(port, "active-backup");

			status = ovsdb_idl_txn_commit_block(txn);
			VLOG_INFO("set bond0 active-backup");
				
			if (status != TXN_INCOMPLETE) { 
				VLOG_INFO("set bond0 active-backup: txn is not incomplete.");
				ovsdb_idl_txn_destroy(txn);
				if (status == TXN_SUCCESS || status == TXN_UNCHANGED) {
					if (status == TXN_SUCCESS) {
						VLOG_INFO("set bond0 active-backup: txn success!");
					} else {
							VLOG_WARN("set bond0 active-backup: failed");
					}
				}
			}
		}
	}


}

bool ovs_dm_process_to_node(int processToNode) {
	char *node_cpulist_path = xasprintf("/sys/devices/system/node/node%d/cpulist", processToNode);
	int cpulist_fd = open(node_cpulist_path, O_RDONLY);

	char buffer[200];
	memset(buffer, 0, sizeof(buffer));
	if (read(cpulist_fd, buffer, sizeof(buffer)) < 0) {
		VLOG_WARN("cannot read /sys/devices/system/node/node/cpulist");
		return false;
	}

	char cpus[200];
	int j = 0;
	memset(cpus, 0, sizeof(cpus));
	for (int i = 0; i < sizeof(cpus) && cpus[i] != ',' && 
					cpus[i] != '\n'; i++) {
		cpus[j++] = buffer[i];
	}
	
	pid_t pid = getpid();
	VLOG_INFO("pid is %d, cpulist is %s", (int)pid, cpus);
	char *cpuset_path = xasprintf("/proc/%d/cpuset", (int)pid);
	int cpuset_fd = open(cpuset_path, O_WRONLY);
	if (write(cpuset_fd, cpus, j - 1) < 0) {
		VLOG_WARN("cannot write proc cpuset");
		return false;
	}
	
	return true;
}

char *ovs_dm_get_error_message(void) {
	return errorMsg;
}
