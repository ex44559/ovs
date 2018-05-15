#include <config.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "ovs-dm.h"
#include "openvswitch/vlog.h"
#include "util.h"



VLOG_DEFINE_THIS_MODULE(ovs_dm);

char errorMsg[200];

void ovs_dm_set_alb_mode(void) {
	char *cmd = xasprintf("ovs-vsctl set port bond0 bond_mode=balance-slb");
	FILE *pp = popen(cmd, "r");

	char buffer[200];
	memset(buffer, 0, sizeof(buffer));
	if (fgets(buffer, sizeof(buffer), pp) != NULL) {
		strcpy(errorMsg, buffer);
	}
	VLOG_INFO("ovs_dm_set_alb_mode res is %s", errorMsg);
	return;
}

void ovs_dm_set_none_alb_mode(void) {
	char *cmd = xasprintf("ovs-vsctl set port bond0 bond_mode=balance-ab");
	FILE *pp = popen(cmd, "r");

	char buffer[200];
	if (fgets(buffer, sizeof(buffer), pp) != NULL) {
		strcpy(errorMsg, buffer);
	}
	return;

}

bool ovs_dm_process_to_node(int processToNode) {
	VLOG_INFO("set process to %d", processToNode);
	return true;
}

char *ovs_dm_get_error_message(void) {
	return errorMsg;
}
