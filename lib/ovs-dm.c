#include "ovs-dm.h"
#include "openvswitch/vlog.h"
#include <stdbool.h>


VLOG_DEFINE_THIS_MODULE(ovs_dm);

char *errorMsg;

void ovs_dm_set_alb_mode(void) {
	
}

void ovs_dm_set_none_alb_mode(void) {

}

bool ovs_dm_process_to_node(int processToNode) {
	VLOG_INFO("set process to %d", processToNode);
	return true;
}

char *ovs_dm_get_error_message(void) {
	char *err = "mealloc error";
	return err;
}
