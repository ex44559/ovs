#include <config.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
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
							VLOG_WARN("set bond0 balance-aslb: failed: set netdev_info");
					}
				}
			}
		}
	}
}

void ovs_dm_set_none_alb_mode(void) {
	char *cmd = xasprintf("ovs-vsctl set port bond0 bond_mode=active-backup");
	FILE *pp = popen(cmd, "r");

	char buffer[200];
	memset(buffer, 0, sizeof(buffer));
	if (fgets(buffer, sizeof(buffer), pp) != NULL) {
		strcpy(errorMsg, buffer);
	}
	VLOG_INFO("ovs_dm_set_none_alb_mode res is %s", errorMsg);
	return;

}

bool ovs_dm_process_to_node(int processToNode) {
	VLOG_INFO("set process to %d", processToNode);
	return true;
}

char *ovs_dm_get_error_message(void) {
	return errorMsg;
}
