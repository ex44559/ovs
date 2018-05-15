#ifndef OVS_DM_H
#define OVS_DM_H 1

#include <string.h>
#include <stdbool.h>
#include "ovsdb-idl.h"

void ovs_dm_set_alb_mode(struct ovsdb_idl *idl);
void ovs_dm_set_none_alb_mode(struct ovsdb_idl *idl);
bool ovs_dm_process_to_node(int processToNode);
char *ovs_dm_get_error_message(void);

#endif