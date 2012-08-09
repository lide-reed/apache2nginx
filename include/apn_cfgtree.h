/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef APN_CONFTREE_H
#define APN_CONFTREE_H

#include "apr_hooks.h"
#include "util_cfgtree.h"
#include "ap_config.h"
#include "apr_pools.h"

#ifdef __cplusplus
extern "C" {
#endif

/** the location in apn conf tree. */

#define APN_UNSET            0x00000000
#define APN_MAIN            0x01000000
#define APN_HTTP_MAIN        0x02000000
#define APN_HTTP_SRV        0x04000000
#define APN_HTTP_LOC        0x08000000
#define APN_MAIN_LOC        0x01100000
#define APN_SRV_LOC            0x04100000
#define APN_LOC                0x05100000

#define APN_ANY                0x0F000000
#define APN_EVENT            0x0C000000
#define APN_SERVER_NO_MASK  0x0000FFFF

#define APN_HTTP_UPS        0x10000000
#define APN_HTTP_SIF        0x20000000
#define APN_HTTP_LIF        0x40000000
#define APN_HTTP_LMT        0x80000000

/** server id included in 0xFF */
#define APN_SRV_MASK        (APN_HTTP_SRV & 0xFF)

/**
 * @brief Structure used to build the config tree.  
 *
 *	The config tree stores the directives which converted 
 *	by conversion hook function within each module.  
 *	Directives that contain other directions, 
 *	such as “Server { ”cause a sub-level to be created, 
 *	where the included directives are stored.  
 *	The closing directive "}" is not stored in the tree.
*/
struct apn_node_s {
/** The current directive */
    const char *directive;
    /** The arguments for the current directive, stored as a space 
     *  separated list */
    const char *args;
    /** The previous directive node in the tree
     *  @defvar apn_node_s *prev */
    struct apn_node_s *prev;
    /** The next directive node in the tree
     *  @defvar apn_node_s *next */
    struct apn_node_s *next;
    /** The first child node of this directive 
     *  @defvar apn_node_s *first_child */
    struct apn_node_s *first_child;
    /** The parent node of this directive 
     *  @defvar apn_node_s *parent */
    struct apn_node_s *parent;

    /** directive's module can store add'l data here */
    void *data;

    /** the nginx conf file which migrated */
    const char *ngx_filename;

    /** the apache conf file which migrated */
    const char *ap_filename;

    /** The line number the directive was on in apache conffile */
    int ngx_line_num;

    /** The line number the directive was on in nginx conffile */
    int ap_line_num;

    /** The location in the nginx conf file, main, http, server... */
    int location;

    /** which server when we have serveral virtualhost, first is 0 */
    int serverid;

    /** need fixup after conversion */
    int need_fixup;

    /** comment */
    const char* comment;
};
typedef struct apn_node_s apn_node_t;

AP_DECLARE(int) apn_init_conftree(apr_pool_t *p, 
                const char** directives, int location);

AP_DECLARE(int) apn_insert_node( apn_node_t *node, int location );

AP_DECLARE(int) apn_output_conftree( apr_file_t *f );

AP_DECLARE(apn_node_t*) apn_new_node(const char* directive, const char* args);

AP_DECLARE(apn_node_t*) apn_dup_node( apn_node_t *node);

AP_DECLARE(int) apn_insert_child( apn_node_t *parent, apn_node_t *node);
AP_DECLARE(apn_node_t*) apn_insert_subtree(apn_node_t *parent, 
                                    apn_node_t *subtree);


AP_DECLARE(apn_node_t*) apn_find_child( apn_node_t *parent, 
                                const char *directive, const char *args);

AP_DECLARE(apr_array_header_t *) apn_find_children( apn_node_t *parent, 
                                const char *directive, const char *args);


AP_DECLARE(apn_node_t*) apn_cat_node( apn_node_t *old, apn_node_t *new);

AP_DECLARE(apn_node_t*) apn_remove_subtree(apn_node_t *subtree);

AP_DECLARE(int) apn_delete_node(apn_node_t *node);

AP_DECLARE(apn_node_t*) apn_get_server_node(int id );

/** insert subtree as the next of the node of new_pos. */
AP_DECLARE(apn_node_t*) apn_insert_as_next(apn_node_t *new_pos, 
                                            apn_node_t *subtree);

// --------------- maybe useless functions 
#if 0
AP_DECLARE(int) apn_get_parent_location(int child_loc);
AP_DECLARE(int) apn_update_node( const char *directive, 
                    const char *args, int location );
AP_DECLARE(apn_node_t*) apn_find_node_in_location( const char *directive, 
                    const char *args, int location );
AP_DECLARE(apn_node_t *) apn_get_last_child( apn_node_t* parent );

/** node if or not server node, "server {" */
AP_DECLARE(int) apn_node_is_server(apn_node_t *node );

#endif
// ----------------------------------------



AP_DECLARE_DATA    extern apn_node_t *apn_conftree;


/** about server */

struct apn_server_s{
    apn_node_t* server;
    struct apn_server_s* next;
};
typedef struct apn_server_s apn_server_t;

extern apn_server_t* apn_server_list;
AP_DECLARE(int) apn_server_insert(apr_pool_t* p, apn_node_t *node );

extern int have_virtual_host;

/** for the store nodes */
struct apn_module_s{
    apn_node_t* directives;
    struct apn_module_s* next;
};
typedef struct apn_module_s apn_module_t;

AP_DECLARE(apn_module_t *) apn_new_module(apn_node_t *node);

AP_DECLARE(apn_module_t *) apn_cat_module(apn_module_t *old, apn_module_t* new);

AP_DECLARE(apn_module_t*) apn_mod_insert_sibling(apn_module_t *mod, 
        const char* directive, const char* args);

AP_DECLARE(apn_module_t*) apn_mod_insert_child(apn_module_t *mod, 
        const char* directive, const char* args);

/** some directive can't converted completely, comment it. */
AP_DECLARE(void) apn_mod_add_comment(
        apn_module_t *mod, 
        const char* comment);
#ifdef __cplusplus
}
#endif
#endif

