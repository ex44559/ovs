#ifndef OVS_DM_H
#define OVS_DM_H 1

#include <string.h>
#include <stdbool.h>

void ovs_dm_set_alb_mode(void);
void ovs_dm_set_none_alb_mode(void);
bool ovs_dm_process_to_node(int processToNode);
char *ovs_dm_get_error_message(void);

#endif