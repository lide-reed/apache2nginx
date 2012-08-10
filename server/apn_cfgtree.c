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

#include "apr.h"
#include "apr_strings.h"
#include "apr_file_io.h"

#include "ap_config.h"
#include "httpd.h"
#include "apn_cfgtree.h"
#include "apn_debug.h"

/** the position on the same level. */
#define PRE_NODE                0x001
#define NEXT_NODE                0x010
#define LAST_NEXT_NODE            0x020
#define NEXT_NODE_MODE            0x0F0
#define FIRST_CHILD_NODE        0x100
#define LAST_NEXT_OF_CHILD_NODE    0x200

/*#define APN_CONFTREE_DEBUG*/

int have_virtual_host = 0;
static apr_pool_t *apn_global_pool = NULL;
apn_node_t* apn_conftree = NULL;
apn_server_t* apn_server_list = NULL;
static apn_node_t* apn_mod_last_inserted_directive = NULL;


static apn_node_t* apn_find_sibling_node( apn_node_t *current, 
        const char* directive, const char* args);
static apr_status_t apn_insert_node_internal( apn_node_t *node,
                              apn_node_t** p,
                              int flag);

/**
 * function define.
 */
AP_DECLARE(int) apn_init_conftree(apr_pool_t *p, 
                    const char** directives, int location)
{
    const char* directive;
    const char* args;
    int i = 0;
    int is_server = 0;
    apn_node_t* new = NULL;
    apn_global_pool = p;

    if( !directives && location == 0){
        apn_info("init conftree.");
        return APR_SUCCESS;
    } else if( !directives ){
        apn_warning("Warning: init conftree error.\n");
        return APR_EGENERAL;
    }

    while (1) {
        directive = directives[i];
        args = directives[i+1];
        if ( !directive ) break;
        i = i+2;
        is_server = !strcmp(directive, "server" );
        if ( have_virtual_host && is_server) 
            continue;

        /** add the server to apn_server list. */
        if ( is_server ) {
            //TODO
            /*apn_add_server*/
        }
        new = apn_new_node(directive, args);
        if (new == NULL) {
            apn_error("Error: failed to creat a new node\n");
            return APR_EGENERAL;
        }

        apn_insert_node( new, location );
    }

    return APR_SUCCESS;
}

/** 
 * @brief insert a node to the conftree.
 * 
 * @param node
 * 
 * @return 
 */
AP_DECLARE(int) apn_insert_node( apn_node_t *node, int location )
{
    /**
     * now the location in the node is indicate the right one.
     */
    apn_node_t **p = NULL;
    int flag = LAST_NEXT_NODE;
    node->location = location;
    switch ( location ) {
        case APN_MAIN:
            /** always insert before http */
            p = apr_palloc( apn_global_pool, sizeof(apn_node_t*));
            *p = apn_find_sibling_node( apn_conftree, "http", NULL);
            flag = PRE_NODE;
            if(!*p) {
                p = &apn_conftree;
                flag = LAST_NEXT_NODE;
            }
            break;
        case APN_EVENT:
            p = apr_palloc( apn_global_pool, sizeof(apn_node_t*));
            *p = apn_find_sibling_node( apn_conftree, "events", NULL);
            flag = LAST_NEXT_OF_CHILD_NODE;
            break;
        case APN_HTTP_MAIN:
            p = apr_palloc( apn_global_pool, sizeof(apn_node_t*));
            apn_node_t *http = 
                apn_find_sibling_node( apn_conftree, "http", NULL);

            apn_node_t *first_server = NULL;
            if (http == NULL) {
                apn_error("The \"http\" section not found.\n");
                return APR_EGENERAL;
            } else {
                first_server = 
                apn_find_sibling_node( http->first_child, "server", NULL);
            }

            if (!first_server){
                *p = http;
                flag = LAST_NEXT_OF_CHILD_NODE;
            }else{
                *p = first_server;
                flag = PRE_NODE;
            }
            break;
        case APN_HTTP_SRV:
            p = apr_palloc( apn_global_pool, sizeof(apn_node_t*));
            if (p == NULL) {
                apn_error("failed to alloc a apn_node.\n");
                return APR_EGENERAL;
            }

            *p = apn_get_server_node( node->serverid );
            if (!*p) {
                apn_error("virtualhost parsing error.\n");
                return APR_EGENERAL;
            }

            flag = LAST_NEXT_OF_CHILD_NODE;
            break;
        default:
            p = &apn_conftree;
            flag = LAST_NEXT_NODE;
            break;
    }

    if ( *p != apn_conftree && *p == NULL ){
        apn_error("p is null when insert node.\n");
        return APR_EGENERAL;
    }

    return apn_insert_node_internal( node, p, flag );
}


AP_DECLARE(apn_node_t*) apn_find_child( apn_node_t *parent, 
                                const char *directive, const char *args)
{
    if ( !apn_conftree ){
        apn_error("apn_conftree is not built yet.\n");
        return NULL;
    }

    if (!directive) {
        apn_warning("directive is null in apn_find_child.\n");
        return NULL;
    }

    if( !parent ) {
        return apn_find_sibling_node(apn_conftree, directive, args);
    }

    return apn_find_sibling_node(parent->first_child, directive, args);
}

AP_DECLARE(apr_array_header_t *) apn_find_children( apn_node_t *parent, 
                                const char *directive, const char *args)
{
    if ( !apn_conftree ){
        apn_error("apn_conftree is not built yet.\n");
        return NULL;
    }

    if (!directive) {
        apn_warning("directive is null in apn_find_children.\n");
        return NULL;
    }

    if( !parent ) parent = apn_conftree;

    apr_array_header_t *children = 
        apr_array_make(apn_global_pool, 1, sizeof(apn_node_t *));

    apn_node_t *found = 
        apn_find_sibling_node(parent->first_child, directive, args);

    apn_node_t **new;
    while(found){
        new = (apn_node_t**)apr_array_push(children);
        *new = found;
        found = apn_find_sibling_node(found->next, directive, args);
    }
    
    return children;
}



/** 
 * @brief get strings.
 * 
 * @param n
 * 
 * @return 
 */
static const char* get_repeat_string(int n, const char *substr)
{
    if(n <= 0) return "";

    char* str= "";
    while(n--){
        str = apr_pstrcat(apn_global_pool, str, substr, NULL);
    }
    return str;
}

/* We need add '#' before eache line */
static void apn_print_multi_comment(apr_pool_t *p,
        apr_file_t *f, const char* str, int depth)
{
    if(!str) return;

    const char* newstr = "# ";
    char* oldstr = apr_pstrdup(p, str);

    int len = strlen(oldstr);
    int i;
    
    const char* next = NULL;
    const char* last = oldstr;
    for(i=0; i<len; i++){
        if(oldstr[i] == '\n'){
            oldstr[i] = '\0';
            next = oldstr + i + 1;
            newstr = apr_pstrcat(p, newstr, last, "\n", 
                    get_repeat_string(depth, "\t"),"# ", NULL);
            last = next;
        }
    }
    newstr = apr_pstrcat(p, newstr, last, "\n", NULL); 

    apr_file_printf(f, newstr);
}


static int apn_output_conftree_internal( apn_node_t *p, apr_file_t *f, int depth)
{
    int rv;
    int seems_parent = 0;

    if (!p || depth < 0 ) {
        return APR_SUCCESS;
    }

    seems_parent = 0;

    int args_is_null = 0;

    if( !p->args ){
        args_is_null = 1;
    } else if( strlen(p->args) == 0 ){
        args_is_null = 1;
    }

    if(!args_is_null){
        if( p->args[strlen(p->args) - 1] == '{'){
            apr_file_printf(f, "\n");
            seems_parent = 1;
        }
    }

    apr_file_printf(f, get_repeat_string(depth, "\t"));
    /*apr_file_printf(f, "%s  %s", p->directive, p->args);*/

    if(p->comment){
        apr_file_printf(f, "\n");
        apr_file_printf(f, get_repeat_string(depth, "\t"));
        apr_file_printf(f, "#\n");

        apr_file_printf(f, get_repeat_string(depth, "\t"));
        /*apr_file_printf(f, "# %s\n", p->comment);*/
        apn_print_multi_comment(apn_global_pool, f, p->comment, depth);

        apr_file_printf(f, get_repeat_string(depth, "\t"));
        apr_file_printf(f, "#\n");
        apr_file_printf(f, get_repeat_string(depth, "\t"));
    }
#ifdef APN_CONFTREE_DEBUG
    const char* location_str;
    switch (p->location ){
        case APN_EVENT:
            location_str = "event";
            break;
        case APN_HTTP_MAIN:
            location_str = "http_main";
            break;
        case APN_MAIN_LOC:
            location_str = "main_location";
            break;
        case APN_HTTP_LOC:
            location_str = "http_location";
            break;
        case APN_HTTP_SRV:
            location_str = "http_server";
            break;
            break;
        case APN_SRV_LOC:
            location_str = "server_location";
            break;
        case APN_MAIN:
            location_str = "main";
            break;
        default: 
            location_str = "";
            break;
    }
    if(!args_is_null){
        apr_file_printf(f, "[%s] %s  %s", 
                location_str, p->directive, p->args);
    }else{
        apr_file_printf(f, "[%s] %s", 
                location_str, p->directive);
    }
#else
    if(!args_is_null){
        apr_file_printf(f, "%s  %s", p->directive, p->args);
    }else{
        apr_file_printf(f, "%s", p->directive);
    }
#endif
    apr_file_printf(f, seems_parent?"\n":";\n");

    if(p->comment && p->first_child == NULL){
        apr_file_printf(f, "\n");
    }

    if( p->first_child ){
        rv = apn_output_conftree_internal(p->first_child, f, depth+1);
        apr_file_printf(f, get_repeat_string(depth,"\t"));
        apr_file_printf(f, "}\n");
    }else if (seems_parent){
        apr_file_printf(f, get_repeat_string(depth,"\t"));
        apr_file_printf(f, "}\n");
    }
    
    if( p->next ){
        rv = apn_output_conftree_internal(p->next, f, depth);
    }

    return APR_SUCCESS;
}

/** 
 * brief output to a file.
 * @param filename
 * @return 
 */
AP_DECLARE(int) apn_output_conftree( apr_file_t *f )
{
    if(!apn_global_pool) {
        apn_error("we have not set pool in apn conftree.\n");
        return APR_EGENERAL;
    }

    apr_status_t rv;

    apn_node_t* p = apn_conftree;
    if ( !p ){
        apn_error("apn_conftree is not built yet.\n");
        return APR_EGENERAL;
    }

    rv = apn_output_conftree_internal(p, f, 0);
    if (rv != APR_SUCCESS ){
        apn_error("output to file error.\n");
        return rv;
    }
    
    return APR_SUCCESS;
}

/** 
 * @brief new node according to directive and args.
 * 
 * @param 
 */
AP_DECLARE(apn_node_t*) apn_new_node(const char* directive, const char* args)
{
    if(!apn_global_pool) {
        apn_error("we have not set pool in apn conftree.\n");
        return NULL;
    }

    apn_node_t *new = 
        apr_palloc( apn_global_pool, sizeof(apn_node_t));

    if (new == NULL) {
        return NULL;
    }

    new->first_child = NULL;
    new->prev = NULL;
    new->next = NULL;
    new->parent = NULL;
    new->data = NULL;
    new->ngx_line_num = 0;
    new->ap_line_num = 0;

    new->directive = apr_pstrdup(apn_global_pool, directive);
    if(args) new->args = apr_pstrdup(apn_global_pool, args);
    new->ngx_filename = NULL;
    new->ap_filename = NULL;

    new->serverid = -1;   // which server.
    new->need_fixup = 0; 
    new->location = APN_HTTP_SRV;
    new->comment = NULL;

    return new;
}

AP_DECLARE(apn_node_t*) apn_dup_node( apn_node_t *node)
{    
    apn_node_t *new = 
        apr_palloc( apn_global_pool, sizeof(apn_node_t));
    new->first_child = node->first_child;
    new->prev = node->prev;
    new->next =  node->next;
    new->parent =node->parent;
    new->data =  node->data;
    new->ngx_line_num = node->ngx_line_num;
    new->ap_line_num = node->ap_line_num;

    new->directive = apr_pstrdup(apn_global_pool, node->directive);
    if(node->args) new->args = apr_pstrdup(apn_global_pool, node->args);
    new->ngx_filename = node->ngx_filename;
    new->ap_filename = node->ap_filename;

    new->serverid = node->serverid;
    new->need_fixup = node->need_fixup; 
    new->location = node->location;
    new->comment = node->comment;

    return new;
}

/** 
 * @brief find a sibling node of current node.
 * 
 * @param current
 * @param directive
 * 
 * @return 
 */
static apn_node_t* apn_find_sibling_node( apn_node_t *current, 
        const char* directive, const char* args)
{
    apn_node_t* p = current;
    while (p){
        if( p->directive && !strcmp(p->directive, directive ) ){
            if(!args) return p;
            if(args && !strcmp(p->args, args)) return p;
        }
        p = p->next;
    }
    return NULL;
}



/** 
 * @brief insert a node acording to current and flags.
 * 
 * @param node
 * @param current
 * @param flag
 * 
 * @return 
 */
static apr_status_t apn_insert_node_internal( apn_node_t *node,
                              apn_node_t** p,
                              int flag)
{
    apn_node_t *current = *p;

    if (!current && (flag & NEXT_NODE_MODE) ) {
        *p = node;
        return APR_SUCCESS;
    }

    switch ( flag ) {
        case PRE_NODE :
            if (!current) {
                apn_error("try to insert to the previous of a null node.\n");
                return APR_EGENERAL;
            }
            apn_node_t *q = current->prev;
            current->prev = node;
            node->prev = q;
            node->next = current;
            if (q) q->next = node;
            node->parent = current->parent;
            break;
        case NEXT_NODE :
            if (current) {
                apn_node_t *q = current->next;
                current->next = node;
                node->prev = current;
                node->next = q;
                if (q) q->prev = node;
                node->parent = current->parent;
            }
            break;
        case LAST_NEXT_NODE :
            if (current) {
                apn_node_t *q = current;
                while ( q && q->next){
                    q = q->next;
                }
                q->next = node;
                node->prev = q;
                node->next = NULL;
                node->parent = q->parent;
            }
            break;
        case FIRST_CHILD_NODE :
            if (!current) {
                apn_error("try to insert to a null node's child.\n");
                return APR_EGENERAL;
            }else{
                apn_node_t *q = current->first_child;
                current->first_child = node;
                node->prev = NULL;
                node->next = q;
                node->parent = current;
                if (q) q->prev = node;
            }

            break;
        case LAST_NEXT_OF_CHILD_NODE :
            if (!current) {
                apn_error("try to insert to a null node's child.\n");
                return APR_EGENERAL;
            }else{
                apn_node_t *q = current->first_child;
                while ( q && q->next){
                    q = q->next;
                }
                node->parent = current;
                node->prev = q;
                node->next = NULL;
                if (!q) {
                    current->first_child = node;
                } else {
                    q->next = node;
                }
            }
            break;

        default:
            break;
    }
    return APR_SUCCESS;
}


AP_DECLARE(int) apn_insert_child( apn_node_t *parent, apn_node_t *node)
{
    int flag = LAST_NEXT_OF_CHILD_NODE;
    if (node && parent){
        return apn_insert_node_internal( node, &parent, flag );
    }

    apn_error("node is null when insert child to apn conftree.\n");
    return APR_EGENERAL;
}

AP_DECLARE(apn_node_t*) apn_insert_subtree(apn_node_t *parent, apn_node_t *subtree)
{
    if (!parent) {
        apn_error("the parent is null when insert subtree.\n");
        return parent;
    }

    /** no error msg but maybe a bug. */
    if(!subtree) return parent;

    /** fixup parent & prev point. 
     *  many module just use next and first_child, so ...
     */
    apn_node_t* p = subtree;
    apn_node_t* q = NULL;
    apr_array_header_t *directives 
        = apr_array_make(apn_global_pool, 1, sizeof(apn_node_t*));

    while(p) {
        p->parent = parent;
        p = p->next;
    }
    
    p = subtree;
    apn_node_t **tmp;
    while(p){
        q = p;
        if ( p->first_child ) {
            if( p->next ) {
                tmp = (apn_node_t**)apr_array_push(directives);
                *tmp = p->next;
            }
            p = p->first_child;
            p->parent = q;
        }else{
            p = p->next;
            if (!p) {
                tmp = (apn_node_t**)apr_array_pop(directives);
                if (tmp) p = *tmp;
            }else{
                p->prev = q;
            }
        }
    }
    /** insert subtree after the last node */
    p = parent->first_child;
    if( !p ){
        parent->first_child = subtree;
    } else {
        while(p->next) p = p->next;
        subtree->prev = p;
        p->next = subtree;
    }

    return parent;
}


AP_DECLARE(apn_node_t*) apn_cat_node( apn_node_t *old, apn_node_t *new)
{
    if ( !old ) {
        return new;
    }

    apn_node_t *node = old;

    while(old->next) old = old->next;

    old->next = new;

    return node;
}

AP_DECLARE(apn_node_t*) apn_remove_subtree(apn_node_t *subtree)
{
    if(!subtree) return NULL;

    apn_node_t *parent = subtree->parent;
    apn_node_t *pnext = subtree->next;
    apn_node_t *prev = subtree->prev;

    if(prev) prev->next = pnext;
    if(pnext) pnext->prev = prev;
    if( parent && parent->first_child == subtree) 
        parent->first_child = pnext;

    return subtree;
}

AP_DECLARE(int) apn_delete_node(apn_node_t *node)
{
    if(!node || node->first_child) {
        apn_warning("delete null node or node have children when delete.\n");
        return APR_EGENERAL;
    }

    apn_node_t *parent = node->parent;
    apn_node_t *pnext = node->next;
    apn_node_t *prev = node->prev;

    if(prev) prev->next = pnext;
    if(pnext) pnext->prev = prev;
    if( parent && parent->first_child == node) 
        parent->first_child = pnext;

    return APR_SUCCESS;
}

/**
 * The operations about server.------------ begin
 */


/** brief we always insert to the first one.
 *  @param 
 *  @param node
 */
AP_DECLARE(int) apn_server_insert(apr_pool_t*p, apn_node_t *node )
{
    if ( !p || !node) return APR_EGENERAL;

    apn_server_t *s = apr_palloc(p, sizeof(apn_server_t));
    s->server = node;

    if(apn_server_list) {

        apn_server_t *last = apn_server_list;
        while(last->next) last = last->next;
        last->next = s;
        s->next = NULL;

    }else{
        apn_server_list = s;
    }

    return APR_SUCCESS;
}

/**
 * The operations about module.------------ begin
 */

AP_DECLARE(apn_module_t *) apn_new_module(apn_node_t *node)
{
    apn_module_t *m = apr_palloc(apn_global_pool, sizeof(apn_module_t));
    m->directives = node;
    m->next = NULL;

    return m;
}

AP_DECLARE(apn_module_t *) apn_cat_module(apn_module_t *old, apn_module_t* new)

{
    if ( !old ) {
        return new;
    }

    apn_module_t *mod = old;

    while(old->next) old = old->next;

    old->next = new;

    return mod;
}

AP_DECLARE(void) apn_mod_add_comment(
        apn_module_t *mod, 
        const char* comment)
{
    if (apn_mod_last_inserted_directive){
        apn_mod_last_inserted_directive->comment = comment;
    }else{
        apn_warning("The last inserted directive is null.");
    }
}

AP_DECLARE(apn_module_t*) apn_mod_insert_sibling(apn_module_t *mod, 
        const char* directive, const char* args)
{
    apn_node_t* new_node = apn_new_node(directive, args);
    apn_node_t* node;

    if (new_node == NULL) {
        apn_mod_last_inserted_directive = NULL;
        apn_warning("Failed to new a node\n");
        return mod;
    }

    if (mod) {
        node = mod->directives;
        while(node->next) node = node->next;
        node->next = new_node;
        new_node->prev = node;
    } else {
        mod = apn_new_module( new_node );
    }

    apn_mod_last_inserted_directive = new_node;
    return mod;
}

AP_DECLARE(apn_module_t*) apn_mod_insert_child(apn_module_t *mod, 
        const char* directive, const char* args)
{
    if( !mod) {
        return apn_mod_insert_sibling(mod, directive, args);
    }

    apn_node_t* new_node = apn_new_node(directive, args);

    apn_node_t* parent = mod->directives;
    while(parent->next) {
        parent = parent->next;
    }

    int rv = apn_insert_child( parent, new_node);

    /**
     * make sure the last inserted directive is responding with this function.
     */
    if (rv != APR_SUCCESS) {
        apn_mod_last_inserted_directive = NULL;
        return NULL;
    }

    apn_mod_last_inserted_directive = new_node;

    return mod;
}

AP_DECLARE(apn_node_t*) apn_get_server_node(int id )
{
    int i = 0;
    apn_node_t* s = apn_server_list->server;
    while(s) {
        i++;
        if (i == id) return s;
        s = s->next;
    }

    return NULL;
}

/** insert subtree as the previous of the node of new_pos. */
AP_DECLARE(apn_node_t*) apn_insert_as_prev(apn_node_t *new_pos, 
                                            apn_node_t *subtree)
{
    if(!subtree || !new_pos) return NULL;

    apn_node_t *pprev = new_pos->prev;

    new_pos->prev = subtree;
    subtree->prev = pprev;
    if(pprev) {
        pprev->next = subtree;
    } else {
        if(new_pos->parent) 
            new_pos->parent->first_child = subtree;
    }
    subtree->parent = new_pos->parent;
    subtree->next = new_pos;
    
    return subtree;
}


/** insert subtree as the next of the node of new_pos. */
AP_DECLARE(apn_node_t*) apn_insert_as_next(apn_node_t *new_pos, 
                                            apn_node_t *subtree)
{
    if(!subtree || !new_pos) return NULL;

    apn_node_t *pnext = new_pos->next;

    new_pos->next = subtree;
    subtree->next = pnext;
    if(pnext) pnext->prev = subtree;
    subtree->prev = new_pos;
    subtree->parent = new_pos->parent;
    
    return subtree;
}


AP_DECLARE(int) apn_node_is_server(apn_node_t *node )
{
    if (!apn_server_list){
        apn_error("server is not built.\n");
        return 0;
    }

    apn_server_t* s = apn_server_list;
    while(s) {
        if(s->server == node) return 1;
        s = s->next;
    }

    return 0;
}



//----------------------- the begin of maybe userlee --------------------------

#if 0

AP_DECLARE(int) apn_get_parent_location(int child_loc)
{
    /** most of directives belongs to server. */
    int parent_loc = APN_HTTP_SRV;

    switch (child_loc){
        case APN_EVENT:
        case APN_HTTP_MAIN:
        case APN_MAIN_LOC:
            parent_loc = APN_MAIN;
            break;
        case APN_HTTP_LOC:
        case APN_HTTP_SRV:
            parent_loc = APN_HTTP_MAIN;
            break;
        case APN_SRV_LOC:
            parent_loc = APN_HTTP_SRV;
            break;
        default: //APN_MAIN 
            apn_warning("the location 0x%x of child is error.\n", child_loc);
            break;
    }
    return parent_loc;
}

AP_DECLARE(int) apn_update_node( const char *directive, 
                    const char *args, int location )
{
    apn_node_t *node = 
        apn_find_node_in_location(directive, args, location);
    if(!node){
        apn_info("no such node found, insert it.\n");
        return apn_insert_node(apn_new_node(directive, args),location );
    }

    node->directive = apr_pstrdup( apn_global_pool, directive);
    node->args = apr_pstrdup( apn_global_pool, args);

    return APR_SUCCESS;
}

AP_DECLARE(apn_node_t*) apn_find_node_in_location( const char *directive, 
                    const char *args, int location )
{
    apn_node_t *start_node = NULL;
    int server_id = -1;

    if(location & APN_HTTP_SRV){
        server_id = location & APN_SRV_MASK;
        location = APN_HTTP_SRV;
    }
    switch (location ){
        case APN_MAIN:
            start_node = apn_conftree;
            break;
        case APN_EVENT:
            start_node = apn_find_sibling_node(apn_conftree, "events", NULL);
            if(start_node) start_node = start_node->first_child;
            break;
        case APN_HTTP_MAIN:
            start_node = apn_find_sibling_node(apn_conftree, "http", NULL);
            if(start_node) start_node = start_node->first_child;
            break;
        case APN_HTTP_SRV:
            start_node = apn_get_server_node(server_id);
            if(start_node) start_node = start_node->first_child;
            break;
        default: 
            start_node = NULL;
            break;
    }

    while(start_node){
        if(directive && args){
            if( (strcasecmp(start_node->directive, directive) == 0 )
                    && (strcasecmp(start_node->args, args) == 0 ) ){
                return start_node;
            }
        }else if (directive){
            if( strcasecmp(start_node->directive, directive) == 0 ){
                return start_node;
            }
        }
        start_node = start_node->next;
    }

    return NULL;
}

AP_DECLARE(apn_node_t *) apn_get_last_child( apn_node_t* parent )
{
    if( !parent) return NULL;

    apn_node_t* child = parent->first_child;

    while(child->next) child = child->next;

    return child;
}

#endif

//----------------------- the end of maybe userlee --------------------------
