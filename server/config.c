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

/*
 * http_config.c: once was auxillary functions for reading httpd's config
 * file and converting filenames into a namespace
 *
 * Rob McCool
 *
 * Wall-to-wall rewrite for Apache... commands which are part of the
 * server core can now be found next door in "http_core.c".  Now contains
 * general command loop, and functions which do bookkeeping for the new
 * Apache config stuff (modules and configuration vectors).
 *
 * rst
 *
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_portable.h"
#include "apr_file_io.h"
#include "apr_fnmatch.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#define CORE_PRIVATE

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_log.h"      /* for errors in parse_htaccess */
#include "http_request.h"  /* for default_handler (see invoke_handler) */
#include "http_main.h"
#include "http_vhost.h"
#include "util_cfgtree.h"
#include "mpm.h"

#define APACHE2NGINX

AP_DECLARE_DATA const char *ap_server_argv0 = NULL;

AP_DECLARE_DATA const char *ap_server_root = NULL;

AP_DECLARE_DATA apr_array_header_t *ap_server_pre_read_config = NULL;
AP_DECLARE_DATA apr_array_header_t *ap_server_post_read_config = NULL;
AP_DECLARE_DATA apr_array_header_t *ap_server_config_defines = NULL;

AP_DECLARE_DATA ap_directive_t *ap_conftree = NULL;

/**
 * whether it is localhost conf depend on user, group, server_root ...
 */
static apn_local_conf_t* apn_local_conf = NULL;
static int apn_is_local_conf = 0;

APR_HOOK_STRUCT(
           APR_HOOK_LINK(header_parser)
           APR_HOOK_LINK(pre_config)
           APR_HOOK_LINK(post_config)
           APR_HOOK_LINK(open_logs)
           APR_HOOK_LINK(child_init)
           APR_HOOK_LINK(handler)
           APR_HOOK_LINK(quick_handler)
           APR_HOOK_LINK(optional_fn_retrieve)
           APR_HOOK_LINK(test_config)
)

AP_IMPLEMENT_HOOK_RUN_ALL(int, header_parser,
                          (request_rec *r), (r), OK, DECLINED)

AP_IMPLEMENT_HOOK_RUN_ALL(int, pre_config,
                          (apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp),
                          (pconf, plog, ptemp), OK, DECLINED)

AP_IMPLEMENT_HOOK_VOID(test_config,
                       (apr_pool_t *pconf, server_rec *s),
                       (pconf, s))

AP_IMPLEMENT_HOOK_RUN_ALL(int, post_config,
                          (apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp, server_rec *s),
                          (pconf, plog, ptemp, s), OK, DECLINED)

/* During the course of debugging I expanded this macro out, so
 * rather than remove all the useful information there is in the
 * following lines, I'm going to leave it here in case anyone
 * else finds it useful.
 *
 * Ben has looked at it and thinks it correct :)
 *
AP_DECLARE(int) ap_hook_post_config(ap_HOOK_post_config_t *pf,
                                    const char * const *aszPre,
                                    const char * const *aszSucc,
                                    int nOrder)
{
    ap_LINK_post_config_t *pHook;

    if (!_hooks.link_post_config) {
        _hooks.link_post_config = apr_array_make(apr_hook_global_pool, 1,
                                                 sizeof(ap_LINK_post_config_t));
        apr_hook_sort_register("post_config", &_hooks.link_post_config);
    }

    pHook = apr_array_push(_hooks.link_post_config);
    pHook->pFunc = pf;
    pHook->aszPredecessors = aszPre;
    pHook->aszSuccessors = aszSucc;
    pHook->nOrder = nOrder;
    pHook->szName = apr_hook_debug_current;

    if (apr_hook_debug_enabled)
        apr_hook_debug_show("post_config", aszPre, aszSucc);
}

AP_DECLARE(apr_array_header_t *) ap_hook_get_post_config(void) {
    return _hooks.link_post_config;
}

AP_DECLARE(int) ap_run_post_config(apr_pool_t *pconf,
                                   apr_pool_t *plog,
                                   apr_pool_t *ptemp,
                                   server_rec *s)
{
    ap_LINK_post_config_t *pHook;
    int n;

    if(!_hooks.link_post_config)
        return;

    pHook = (ap_LINK_post_config_t *)_hooks.link_post_config->elts;
    for (n = 0; n < _hooks.link_post_config->nelts; ++n)
        pHook[n].pFunc (pconf, plog, ptemp, s);
}
 */

AP_IMPLEMENT_HOOK_RUN_ALL(int, open_logs,
                          (apr_pool_t *pconf, apr_pool_t *plog,
                           apr_pool_t *ptemp, server_rec *s),
                          (pconf, plog, ptemp, s), OK, DECLINED)

AP_IMPLEMENT_HOOK_VOID(child_init,
                       (apr_pool_t *pchild, server_rec *s),
                       (pchild, s))

AP_IMPLEMENT_HOOK_RUN_FIRST(int, handler, (request_rec *r),
                            (r), DECLINED)

AP_IMPLEMENT_HOOK_RUN_FIRST(int, quick_handler, (request_rec *r, int lookup),
                            (r, lookup), DECLINED)

AP_IMPLEMENT_HOOK_VOID(optional_fn_retrieve, (void), ())

/****************************************************************
 *
 * We begin with the functions which deal with the linked list
 * of modules which control just about all of the server operation.
 */

/* total_modules is the number of modules that have been linked
 * into the server.
 */
static int total_modules = 0;

/* dynamic_modules is the number of modules that have been added
 * after the pre-loaded ones have been set up. It shouldn't be larger
 * than DYNAMIC_MODULE_LIMIT.
 */
static int dynamic_modules = 0;

AP_DECLARE_DATA module *ap_top_module = NULL;
AP_DECLARE_DATA module **ap_loaded_modules=NULL;

static apr_hash_t *ap_config_hash = NULL;

typedef int (*handler_func)(request_rec *);
typedef void *(*dir_maker_func)(apr_pool_t *, char *);
typedef void *(*merger_func)(apr_pool_t *, void *, void *);
typedef void *(*apn_convert_server_config_func)(apr_pool_t *, 
                        cmd_parms *parms, ap_conf_vector_t*);
typedef void *(*apn_convert_dir_config_func)(apr_pool_t *, 
                        cmd_parms *parms, ap_conf_vector_t*);

/* maximum nesting level for config directories */
#ifndef AP_MAX_INCLUDE_DIR_DEPTH
#define AP_MAX_INCLUDE_DIR_DEPTH (128)
#endif

/* Dealing with config vectors.  These are associated with per-directory,
 * per-server, and per-request configuration, and have a void* pointer for
 * each modules.  The nature of the structure pointed to is private to the
 * module in question... the core doesn't (and can't) know.  However, there
 * are defined interfaces which allow it to create instances of its private
 * per-directory and per-server structures, and to merge the per-directory
 * structures of a directory and its subdirectory (producing a new one in
 * which the defaults applying to the base directory have been properly
 * overridden).
 */

static ap_conf_vector_t *create_empty_config(apr_pool_t *p)
{
    void *conf_vector = apr_pcalloc(p, sizeof(void *) *
                                    (total_modules + DYNAMIC_MODULE_LIMIT));
    return conf_vector;
}

static ap_conf_vector_t *create_default_per_dir_config(apr_pool_t *p)
{
    void **conf_vector = apr_pcalloc(p, sizeof(void *) *
                                     (total_modules + DYNAMIC_MODULE_LIMIT));
    module *modp;

    for (modp = ap_top_module; modp; modp = modp->next) {
        dir_maker_func df = modp->create_dir_config;

        if (df)
            conf_vector[modp->module_index] = (*df)(p, NULL);
    }

    return (ap_conf_vector_t *)conf_vector;
}

AP_CORE_DECLARE(ap_conf_vector_t *) ap_merge_per_dir_configs(apr_pool_t *p,
                                           ap_conf_vector_t *base,
                                           ap_conf_vector_t *new_conf)
{
    void **conf_vector = apr_palloc(p, sizeof(void *) * total_modules);
    void **base_vector = (void **)base;
    void **new_vector = (void **)new_conf;
    module *modp;

    for (modp = ap_top_module; modp; modp = modp->next) {
        int i = modp->module_index;

        if (!new_vector[i]) {
            conf_vector[i] = base_vector[i];
        }
        else {
            merger_func df = modp->merge_dir_config;
            if (df && base_vector[i]) {
                conf_vector[i] = (*df)(p, base_vector[i], new_vector[i]);
            }
            else
                conf_vector[i] = new_vector[i];
        }
    }

    return (ap_conf_vector_t *)conf_vector;
}

static ap_conf_vector_t *create_server_config(apr_pool_t *p, server_rec *s)
{
    void **conf_vector = apr_pcalloc(p, sizeof(void *) *
                                     (total_modules + DYNAMIC_MODULE_LIMIT));
    module *modp;

    for (modp = ap_top_module; modp; modp = modp->next) {
        if (modp->create_server_config)
            conf_vector[modp->module_index] = (*modp->create_server_config)(p, s);
    }

    return (ap_conf_vector_t *)conf_vector;
}

static void merge_server_configs(apr_pool_t *p, ap_conf_vector_t *base,
                                 ap_conf_vector_t *virt)
{
    /* Can reuse the 'virt' vector for the spine of it, since we don't
     * have to deal with the moral equivalent of .htaccess files here...
     */

    void **base_vector = (void **)base;
    void **virt_vector = (void **)virt;
    module *modp;

    for (modp = ap_top_module; modp; modp = modp->next) {
        merger_func df = modp->merge_server_config;
        int i = modp->module_index;

        if (!virt_vector[i])
            virt_vector[i] = base_vector[i];
        else if (df)
            virt_vector[i] = (*df)(p, base_vector[i], virt_vector[i]);
    }
}

AP_CORE_DECLARE(ap_conf_vector_t *) ap_create_request_config(apr_pool_t *p)
{
    return create_empty_config(p);
}

AP_CORE_DECLARE(ap_conf_vector_t *) ap_create_conn_config(apr_pool_t *p)
{
    return create_empty_config(p);
}

AP_CORE_DECLARE(ap_conf_vector_t *) ap_create_per_dir_config(apr_pool_t *p)
{
    return create_empty_config(p);
}

/* Invoke the filter_init_func for all filters with FILTERS where f->r
 * matches R.  Restricting to a matching R avoids re-running init
 * functions for filters configured for r->main where r is a
 * subrequest.  */
#ifndef APACHE2NGINX
static int invoke_filter_init(request_rec *r, ap_filter_t *filters)
{
    while (filters) {
        if (filters->frec->filter_init_func && filters->r == r) {
            int result = filters->frec->filter_init_func(filters);
            if (result != OK) {
                return result;
            }
        }
        filters = filters->next;
    }
    return OK;
}
#endif /* APACHE2NGINX */

AP_CORE_DECLARE(int) ap_invoke_handler(request_rec *r)
{
#ifndef APACHE2NGINX
    const char *handler;
    const char *p;
    int result;
    const char *old_handler = r->handler;
    const char *ignore;

    /*
     * The new insert_filter stage makes the most sense here.  We only use
     * it when we are going to run the request, so we must insert filters
     * if any are available.  Since the goal of this phase is to allow all
     * modules to insert a filter if they want to, this filter returns
     * void.  I just can't see any way that this filter can reasonably
     * fail, either your modules inserts something or it doesn't.  rbb
     */
    ap_run_insert_filter(r);

    /* Before continuing, allow each filter that is in the two chains to
     * run their init function to let them do any magic before we could
     * start generating data.
     */
    result = invoke_filter_init(r, r->input_filters);
    if (result != OK) {
        return result;
    }
    result = invoke_filter_init(r, r->output_filters);
    if (result != OK) {
        return result;
    }

    if (!r->handler) {
        handler = r->content_type ? r->content_type : ap_default_type(r);
        if ((p=ap_strchr_c(handler, ';')) != NULL) {
            char *new_handler = (char *)apr_pmemdup(r->pool, handler,
                                                    p - handler + 1);
            char *p2 = new_handler + (p - handler);
            handler = new_handler;

            /* MIME type arguments */
            while (p2 > handler && p2[-1] == ' ')
                --p2; /* strip trailing spaces */

            *p2='\0';
        }

        r->handler = handler;
    }

    result = ap_run_handler(r);

    r->handler = old_handler;

    if (result == DECLINED && r->handler && r->filename) {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
            "handler \"%s\" not found for: %s", r->handler, r->filename);
    }
    if ((result != OK) && (result != DONE) && (result != DECLINED)
        && (result != AP_FILTER_ERROR)
        && !ap_is_HTTP_VALID_RESPONSE(result)) {
        /* If a module is deliberately returning something else
         * (request_rec in non-HTTP or proprietary extension?)
         * let it set a note to allow it explicitly.
         * Otherwise, a return code that is neither reserved nor HTTP
         * is a bug, as in PR#31759.
         */
        ignore = apr_table_get(r->notes, "HTTP_IGNORE_RANGE");
        if (!ignore) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Handler for %s returned invalid result code %d",
                          r->handler, result);
            result = HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return result == DECLINED ? HTTP_INTERNAL_SERVER_ERROR : result;
#else
    return 0;
#endif /* APACHE2NGINX */
}

AP_DECLARE(int) ap_method_is_limited(cmd_parms *cmd, const char *method)
{
    int methnum;

    methnum = ap_method_number_of(method);

    /*
     * A method number either hardcoded into apache or
     * added by a module and registered.
     */
    if (methnum != M_INVALID) {
        return (cmd->limited & (AP_METHOD_BIT << methnum)) ? 1 : 0;
    }

    return 0; /* not found */
}

AP_DECLARE(void) ap_register_hooks(module *m, apr_pool_t *p)
{
    if (m->register_hooks) {
        if (getenv("SHOW_HOOKS")) {
            printf("Registering hooks for %s\n", m->name);
            apr_hook_debug_enabled = 1;
        }

        apr_hook_debug_current = m->name;
        m->register_hooks(p);
    }
}

static void ap_add_module_commands(module *m, apr_pool_t *p);

typedef struct ap_mod_list_struct ap_mod_list;
struct ap_mod_list_struct {
    struct ap_mod_list_struct *next;
    module *m;
    const command_rec *cmd;
};

static apr_status_t reload_conf_hash(void *baton)
{
    ap_config_hash = NULL;
    return APR_SUCCESS;
}

static void rebuild_conf_hash(apr_pool_t *p, int add_prelinked)
{
    module **m;

    ap_config_hash = apr_hash_make(p);

    apr_pool_cleanup_register(p, NULL, reload_conf_hash,
                              apr_pool_cleanup_null);
    if (add_prelinked) {
        for (m = ap_prelinked_modules; *m != NULL; m++) {
            ap_add_module_commands(*m, p);
        }
    }
}

static void ap_add_module_commands(module *m, apr_pool_t *p)
{
    apr_pool_t *tpool;
    ap_mod_list *mln;
    const command_rec *cmd;
    char *dir;

    cmd = m->cmds;

    if (ap_config_hash == NULL) {
        rebuild_conf_hash(p, 0);
    }

    tpool = apr_hash_pool_get(ap_config_hash);

    while (cmd && cmd->name) {
        mln = apr_palloc(tpool, sizeof(ap_mod_list));
        mln->cmd = cmd;
        mln->m = m;
        dir = apr_pstrdup(tpool, cmd->name);

        ap_str_tolower(dir);

        mln->next = apr_hash_get(ap_config_hash, dir, APR_HASH_KEY_STRING);
        apr_hash_set(ap_config_hash, dir, APR_HASH_KEY_STRING, mln);
        ++cmd;
    }
}


/* One-time setup for precompiled modules --- NOT to be done on restart */

AP_DECLARE(const char *) ap_add_module(module *m, apr_pool_t *p)
{
    /* This could be called from a LoadModule httpd.conf command,
     * after the file has been linked and the module structure within it
     * teased out...
     */

    if (m->version != MODULE_MAGIC_NUMBER_MAJOR) {
        return apr_psprintf(p, "Module \"%s\" is not compatible with this "
                            "version of Apache (found %d, need %d). Please "
                            "contact the vendor for the correct version.",
                            m->name, m->version, MODULE_MAGIC_NUMBER_MAJOR);
    }

    if (m->next == NULL) {
        m->next = ap_top_module;
        ap_top_module = m;
    }

    if (m->module_index == -1) {
        m->module_index = total_modules++;
        dynamic_modules++;

        if (dynamic_modules > DYNAMIC_MODULE_LIMIT) {
            return apr_psprintf(p, "Module \"%s\" could not be loaded, "
                                "because the dynamic module limit was "
                                "reached. Please increase "
                                "DYNAMIC_MODULE_LIMIT and recompile.", m->name);
        }
    }

    /* Some C compilers put a complete path into __FILE__, but we want
     * only the filename (e.g. mod_includes.c). So check for path
     * components (Unix and DOS), and remove them.
     */

    if (ap_strrchr_c(m->name, '/'))
        m->name = 1 + ap_strrchr_c(m->name, '/');

    if (ap_strrchr_c(m->name, '\\'))
        m->name = 1 + ap_strrchr_c(m->name, '\\');

#ifdef _OSD_POSIX
    /* __FILE__ =
     * "*POSIX(/home/martin/apache/src/modules/standard/mod_info.c)"
     */

    /* We cannot fix the string in-place, because it's const */
    if (m->name[strlen(m->name)-1] == ')') {
        char *tmp = strdup(m->name); /* FIXME: memory leak, albeit a small one */
        tmp[strlen(tmp)-1] = '\0';
        m->name = tmp;
    }
#endif /*_OSD_POSIX*/

    ap_add_module_commands(m, p);
    /*  FIXME: is this the right place to call this?
     *  It doesn't appear to be
     */
    ap_register_hooks(m, p);

    return NULL;
}

/*
 * remove_module undoes what add_module did. There are some caveats:
 * when the module is removed, its slot is lost so all the current
 * per-dir and per-server configurations are invalid. So we should
 * only ever call this function when you are invalidating almost
 * all our current data. I.e. when doing a restart.
 */

AP_DECLARE(void) ap_remove_module(module *m)
{
    module *modp;

    modp = ap_top_module;
    if (modp == m) {
        /* We are the top module, special case */
        ap_top_module = modp->next;
        m->next = NULL;
    }
    else {
        /* Not the top module, find use. When found modp will
         * point to the module _before_ us in the list
         */

        while (modp && modp->next != m) {
            modp = modp->next;
        }

        if (!modp) {
            /* Uh-oh, this module doesn't exist */
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, NULL,
                         "Cannot remove module %s: not found in module list",
                         m->name);
            return;
        }

        /* Eliminate us from the module list */
        modp->next = modp->next->next;
    }

    m->module_index = -1; /* simulate being unloaded, should
                           * be unnecessary */
    dynamic_modules--;
    total_modules--;
}

AP_DECLARE(const char *) ap_add_loaded_module(module *mod, apr_pool_t *p)
{
    module **m;
    const char *error;

    /*
     *  Add module pointer to top of chained module list
     */
    error = ap_add_module(mod, p);
    if (error) {
        return error;
    }

    /*
     *  And module pointer to list of loaded modules
     *
     *  Notes: 1. ap_add_module() would already complain if no more space
     *            exists for adding a dynamically loaded module
     *         2. ap_add_module() accepts double inclusion, so we have
     *            to accept this, too.
     */
    for (m = ap_loaded_modules; *m != NULL; m++)
        ;
    *m++ = mod;
    *m = NULL;

    return NULL;
}

AP_DECLARE(void) ap_remove_loaded_module(module *mod)
{
    module **m;
    module **m2;
    int done;

    /*
     *  Remove module pointer from chained module list
     */
    ap_remove_module(mod);

    /*
     *  Remove module pointer from list of loaded modules
     *
     *  Note: 1. We cannot determine if the module was successfully
     *           removed by ap_remove_module().
     *        2. We have not to complain explicity when the module
     *           is not found because ap_remove_module() did it
     *           for us already.
     */
    for (m = m2 = ap_loaded_modules, done = 0; *m2 != NULL; m2++) {
        if (*m2 == mod && done == 0)
            done = 1;
        else
            *m++ = *m2;
    }

    *m = NULL;
}

AP_DECLARE(const char *) ap_setup_prelinked_modules(process_rec *process)
{
    module **m;
    module **m2;
    const char *error;

    apr_hook_global_pool=process->pconf;

    rebuild_conf_hash(process->pconf, 0);

    /*
     *  Initialise total_modules variable and module indices
     */
    total_modules = 0;
    for (m = ap_preloaded_modules; *m != NULL; m++)
        (*m)->module_index = total_modules++;

    /*
     *  Initialise list of loaded modules
     */
    ap_loaded_modules = (module **)apr_palloc(process->pool,
        sizeof(module *) * (total_modules + DYNAMIC_MODULE_LIMIT + 1));

    if (ap_loaded_modules == NULL) {
        return "Ouch! Out of memory in ap_setup_prelinked_modules()!";
    }

    for (m = ap_preloaded_modules, m2 = ap_loaded_modules; *m != NULL; )
        *m2++ = *m++;

    *m2 = NULL;

    /*
     *   Initialize chain of linked (=activate) modules
     */
    for (m = ap_prelinked_modules; *m != NULL; m++) {
        error = ap_add_module(*m, process->pconf);
        if (error) {
            return error;
        }
    }

    apr_hook_sort_all();

    return NULL;
}

AP_DECLARE(const char *) ap_find_module_name(module *m)
{
    return m->name;
}

AP_DECLARE(module *) ap_find_linked_module(const char *name)
{
    module *modp;

    for (modp = ap_top_module; modp; modp = modp->next) {
        if (strcmp(modp->name, name) == 0)
            return modp;
    }

    return NULL;
}

/*****************************************************************
 *
 * Resource, access, and .htaccess config files now parsed by a common
 * command loop.
 *
 * Let's begin with the basics; parsing the line and
 * invoking the function...
 */

#define AP_MAX_ARGC 64

static const char *invoke_cmd(const command_rec *cmd, cmd_parms *parms,
                              void *mconfig, const char *args)
{
    char *w, *w2, *w3;
    const char *errmsg = NULL;

    if ((parms->override & cmd->req_override) == 0)
        return apr_pstrcat(parms->pool, cmd->name, " not allowed here", NULL);

    parms->info = cmd->cmd_data;
    parms->cmd = cmd;

    switch (cmd->args_how) {
    case RAW_ARGS:
#ifdef RESOLVE_ENV_PER_TOKEN
        args = ap_resolve_env(parms->pool,args);
#endif
        return cmd->AP_RAW_ARGS(parms, mconfig, args);

    case TAKE_ARGV:
        {
            char *argv[AP_MAX_ARGC];
            int argc = 0;

            do {
                w = ap_getword_conf(parms->pool, &args);
                if (*w == '\0' && *args == '\0') {
                    break;
                }
                argv[argc] = w;
                argc++;
            } while (argc < AP_MAX_ARGC && *args != '\0');

            return cmd->AP_TAKE_ARGV(parms, mconfig, argc, argv);
        }

    case NO_ARGS:
        if (*args != 0)
            return apr_pstrcat(parms->pool, cmd->name, " takes no arguments",
                               NULL);

        return cmd->AP_NO_ARGS(parms, mconfig);

    case TAKE1:
        w = ap_getword_conf(parms->pool, &args);

        if (*w == '\0' || *args != 0)
            return apr_pstrcat(parms->pool, cmd->name, " takes one argument",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->AP_TAKE1(parms, mconfig, w);

    case TAKE2:
        w = ap_getword_conf(parms->pool, &args);
        w2 = ap_getword_conf(parms->pool, &args);

        if (*w == '\0' || *w2 == '\0' || *args != 0)
            return apr_pstrcat(parms->pool, cmd->name, " takes two arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->AP_TAKE2(parms, mconfig, w, w2);

    case TAKE12:
        w = ap_getword_conf(parms->pool, &args);
        w2 = ap_getword_conf(parms->pool, &args);

        if (*w == '\0' || *args != 0)
            return apr_pstrcat(parms->pool, cmd->name, " takes 1-2 arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->AP_TAKE2(parms, mconfig, w, *w2 ? w2 : NULL);

    case TAKE3:
        w = ap_getword_conf(parms->pool, &args);
        w2 = ap_getword_conf(parms->pool, &args);
        w3 = ap_getword_conf(parms->pool, &args);

        if (*w == '\0' || *w2 == '\0' || *w3 == '\0' || *args != 0)
            return apr_pstrcat(parms->pool, cmd->name, " takes three arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

    case TAKE23:
        w = ap_getword_conf(parms->pool, &args);
        w2 = ap_getword_conf(parms->pool, &args);
        w3 = *args ? ap_getword_conf(parms->pool, &args) : NULL;

        if (*w == '\0' || *w2 == '\0' || *args != 0)
            return apr_pstrcat(parms->pool, cmd->name,
                               " takes two or three arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

    case TAKE123:
        w = ap_getword_conf(parms->pool, &args);
        w2 = *args ? ap_getword_conf(parms->pool, &args) : NULL;
        w3 = *args ? ap_getword_conf(parms->pool, &args) : NULL;

        if (*w == '\0' || *args != 0)
            return apr_pstrcat(parms->pool, cmd->name,
                               " takes one, two or three arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

    case TAKE13:
        w = ap_getword_conf(parms->pool, &args);
        w2 = *args ? ap_getword_conf(parms->pool, &args) : NULL;
        w3 = *args ? ap_getword_conf(parms->pool, &args) : NULL;

        if (*w == '\0' || (w2 && *w2 && !w3) || *args != 0)
            return apr_pstrcat(parms->pool, cmd->name,
                               " takes one or three arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        return cmd->AP_TAKE3(parms, mconfig, w, w2, w3);

    case ITERATE:
        while (*(w = ap_getword_conf(parms->pool, &args)) != '\0') {

            errmsg = cmd->AP_TAKE1(parms, mconfig, w);

            if (errmsg && strcmp(errmsg, DECLINE_CMD) != 0)
                return errmsg;
        }

        return errmsg;

    case ITERATE2:
        w = ap_getword_conf(parms->pool, &args);

        if (*w == '\0' || *args == 0)
            return apr_pstrcat(parms->pool, cmd->name,
                               " requires at least two arguments",
                               cmd->errmsg ? ", " : NULL, cmd->errmsg, NULL);

        while (*(w2 = ap_getword_conf(parms->pool, &args)) != '\0') {

            errmsg = cmd->AP_TAKE2(parms, mconfig, w, w2);

            if (errmsg && strcmp(errmsg, DECLINE_CMD) != 0)
                return errmsg;
        }

        return errmsg;

    case FLAG:
        w = ap_getword_conf(parms->pool, &args);

        if (*w == '\0' || (strcasecmp(w, "on") && strcasecmp(w, "off")))
            return apr_pstrcat(parms->pool, cmd->name, " must be On or Off",
                               NULL);

        return cmd->AP_FLAG(parms, mconfig, strcasecmp(w, "off") != 0);

    default:
        return apr_pstrcat(parms->pool, cmd->name,
                           " is improperly configured internally (server bug)",
                           NULL);
    }
}

AP_CORE_DECLARE(const command_rec *) ap_find_command(const char *name,
                                                     const command_rec *cmds)
{
    while (cmds->name) {
        if (!strcasecmp(name, cmds->name))
            return cmds;

        ++cmds;
    }

    return NULL;
}

AP_CORE_DECLARE(const command_rec *) ap_find_command_in_modules(
                                          const char *cmd_name, module **mod)
{
    const command_rec *cmdp;
    module *modp;

    for (modp = *mod; modp; modp = modp->next) {
        if (modp->cmds && (cmdp = ap_find_command(cmd_name, modp->cmds))) {
            *mod = modp;
            return cmdp;
        }
    }

    return NULL;
}

AP_CORE_DECLARE(void *) ap_set_config_vectors(server_rec *server,
                                              ap_conf_vector_t *section_vector,
                                              const char *section,
                                              module *mod, apr_pool_t *pconf)
{
    void *section_config = ap_get_module_config(section_vector, mod);
    void *server_config = ap_get_module_config(server->module_config, mod);

    if (!section_config && mod->create_dir_config) {
        section_config = (*mod->create_dir_config)(pconf, (char *)section);
        ap_set_module_config(section_vector, mod, section_config);
    }

    if (!server_config && mod->create_server_config) {
        server_config = (*mod->create_server_config)(pconf, server);
        ap_set_module_config(server->module_config, mod, server_config);
    }

    return section_config;
}

static const char *execute_now(char *cmd_line, const char *args,
                               cmd_parms *parms,
                               apr_pool_t *p, apr_pool_t *ptemp,
                               ap_directive_t **sub_tree,
                               ap_directive_t *parent);

static const char *ap_build_config_sub(apr_pool_t *p, apr_pool_t *temp_pool,
                                       const char *l, cmd_parms *parms,
                                       ap_directive_t **current,
                                       ap_directive_t **curr_parent,
                                       ap_directive_t **conftree)
{
    const char *retval = NULL;
    const char *args;
    char *cmd_name;
    ap_directive_t *newdir;
    module *mod = ap_top_module;
    const command_rec *cmd;

    if (*l == '#' || *l == '\0')
        return NULL;

#if RESOLVE_ENV_PER_TOKEN
    args = l;
#else
    args = ap_resolve_env(temp_pool, l);
#endif

    cmd_name = ap_getword_conf(p, &args);
    if (*cmd_name == '\0') {
        /* Note: this branch should not occur. An empty line should have
         * triggered the exit further above.
         */
        return NULL;
    }

    if (cmd_name[1] != '/') {
        char *lastc = cmd_name + strlen(cmd_name) - 1;
        if (*lastc == '>') {
            *lastc = '\0' ;
        }
        if (cmd_name[0] == '<' && *args == '\0') {
            args = ">";
        }
    }

    newdir = apr_pcalloc(p, sizeof(ap_directive_t));
    newdir->filename = parms->config_file->name;
    newdir->line_num = parms->config_file->line_number;
    newdir->directive = cmd_name;
    newdir->args = apr_pstrdup(p, args);
    newdir->flag = parms->flag;
    newdir->errmsg = NULL;

    if ((cmd = ap_find_command_in_modules(cmd_name, &mod)) != NULL) {

        /** Here, only 2 cases to need process */
        unsigned int flag = parms->flag;
        if ( flag & PARAM_NEEDLESS_PROCESS){
            newdir->errmsg = MSG_NEEDLESS_PROCESS;
        }else if ( flag & PARAM_UNRECOGNIZED){
            newdir->errmsg = MSG_UNRECOGNIZED_MODULE;
		} else if (cmd->req_override & EXEC_ON_READ) {
            ap_directive_t *sub_tree = NULL;

            /*parms->err_directive = newdir;*/
            retval = execute_now(cmd_name, args, parms, p, temp_pool,
                                 &sub_tree, *curr_parent);

			if (retval) {
				newdir->flag = parms->flag;
				parms->flag = PARAM_UNDEFINE;
				newdir->errmsg = retval;
				
				if(newdir->flag == PARAM_UNDEFINE)
					newdir->flag = PARAM_UNRECOGNIZED;
			}
			*current = ap_add_node(curr_parent, *current, newdir, 0);

            if (*current) {
                (*current)->next = sub_tree;
            }
            else {
                *current = sub_tree;
                if (*curr_parent) {
                    (*curr_parent)->first_child = (*current);
                }
                if (*current) {
                    (*current)->parent = (*curr_parent);
                }
            }
            if (*current) {
                if (!*conftree) {
                    /* Before walking *current to the end of the list,
                     * set the head to *current.
                     */
                    *conftree = *current;
                }
                while ((*current)->next != NULL) {
                    (*current) = (*current)->next;
                    (*current)->parent = (*curr_parent);
                }
            }
			return NULL;
        }
    }

    if (cmd_name[0] == '<') {
        if (cmd_name[1] != '/') {
            (*current) = ap_add_node(curr_parent, *current, newdir, 1);
        }
        else if (*curr_parent == NULL) {
            parms->err_directive = newdir;
            retval = apr_pstrcat(p, cmd_name,
                               " without matching <", cmd_name + 2,
                               " section", NULL);

			if (retval) {
				newdir->errmsg = retval;
				newdir->flag = PARAM_ERROR;
			}
			*current = ap_add_node(curr_parent, *current, newdir, 0);
			return NULL;
        } else {
            char *bracket = cmd_name + strlen(cmd_name) - 1;

            if (*bracket != '>') {
                parms->err_directive = newdir;
                retval = apr_pstrcat(p, cmd_name,
                                   "> directive missing closing '>'", NULL);
				if (retval) {
					newdir->errmsg = retval;
					newdir->flag = PARAM_ERROR;
				}
				*current = ap_add_node(curr_parent, *current, newdir, 0);
				return NULL;
            }

            *bracket = '\0';

            if (strcasecmp(cmd_name + 2,
                           (*curr_parent)->directive + 1) != 0) {
                parms->err_directive = newdir;
                retval = apr_pstrcat(p, "Expected </",
                                   (*curr_parent)->directive + 1, "> but saw ",
                                   cmd_name, ">", NULL);
				if (retval) {
					newdir->errmsg = retval;
					newdir->flag = PARAM_ERROR;
				}
				*current = ap_add_node(curr_parent, *current, newdir, 0);
				return NULL;
            }

            *bracket = '>';

            /* done with this section; move up a level */
            *current = *curr_parent;
            *curr_parent = (*current)->parent;
        }
    }
    else {
        *current = ap_add_node(curr_parent, *current, newdir, 0);
    }

    return NULL;
}

AP_DECLARE(const char *) ap_build_cont_config(apr_pool_t *p,
                                              apr_pool_t *temp_pool,
                                              cmd_parms *parms,
                                              ap_directive_t **current,
                                              ap_directive_t **curr_parent,
                                              char *orig_directive)
{
    char *l;
    char *bracket;
    const char *retval;
    ap_directive_t *sub_tree = NULL;

    /* Since this function can be called recursively, allocate
     * the temporary 8k string buffer from the temp_pool rather
     * than the stack to avoid over-running a fixed length stack.
     */
    l = apr_palloc(temp_pool, MAX_STRING_LEN);

    bracket = apr_pstrcat(p, orig_directive + 1, ">", NULL);
    while (!(ap_cfg_getline(l, MAX_STRING_LEN, parms->config_file))) {
        if (!memcmp(l, "</", 2)
            && (strcasecmp(l + 2, bracket) == 0)
            && (*curr_parent == NULL)) {
            break;
        }
        retval = ap_build_config_sub(p, temp_pool, l, parms, current,
                                     curr_parent, &sub_tree);
        if (retval != NULL)
            return retval;

        if (sub_tree == NULL) {
            sub_tree = *curr_parent;
        }

        if (sub_tree == NULL) {
            sub_tree = *current;
        }
    }

    *current = sub_tree;
    return NULL;
}

/*
 * If we have write the hook for one module,
 * we can just think it been supported.
 * In default_list, no any hook but we support 
 * and convert directives in core.c.
 *
 */
static int apn_module_is_supported(module *modp)
{
	if(!modp) return 0;

	const char* default_list[] = {
		"http_core.c",
		"mod_so.c",
		NULL
	};

	if (modp->apn_convert_dir_config || 
			modp->apn_convert_server_config ) {
		return 1;
	}else {
		const char** name;
		for( name = default_list; *name; name++){
			if(!strcasecmp(modp->name, *name)){
				return 1;
			}
		}
	}

	return 0;
}

AP_DECLARE(void) apn_set_unsupport(cmd_parms *parms, const char* msg)
{
    if(parms && parms->directive){
        parms->directive->flag = 
			parms->directive->flag | PARAM_UNSUPPORTED;

        /* support multi-lines when not just no relevant msg */
        if( parms->directive->errmsg && 
                strcasecmp(msg, MSG_NO_RELEVANT) != 0 ){
            parms->directive->errmsg = apr_pstrcat(parms->pool, 
                        parms->directive->errmsg, "\n     ", msg, NULL);
        } else {
            parms->directive->errmsg = msg;
        }
    }
}

static const char *apn_get_module_name(apr_pool_t *p, 
        const char *directive)
{
    char *dir = apr_pstrdup(p, directive);
    ap_str_tolower(dir);
    ap_mod_list *ml;
    ml = apr_hash_get(ap_config_hash, dir, APR_HASH_KEY_STRING);

    /*if (ml == NULL) {
        apn_warning("perhaps misspelled or defined by a module.");
    }*/

    for ( ; ml != NULL; ml = ml->next) {
        if(ml->m) return ml->m->name;
    }

    return NULL;
     
}

static const char *ap_walk_config_sub(const ap_directive_t *current,
                                      cmd_parms *parms,
                                      ap_conf_vector_t *section_vector)
{
    const command_rec *cmd;
    ap_mod_list *ml;
    char *dir = apr_pstrdup(parms->pool, current->directive);

    ap_str_tolower(dir);

    ml = apr_hash_get(ap_config_hash, dir, APR_HASH_KEY_STRING);

    if (ml == NULL) {
        parms->err_directive = current;
        parms->flag |= PARAM_UNRECOGNIZED;
		return apr_pstrcat(parms->pool, "Unrecognized command '",
						   current->directive,
						   "', perhaps misspelled or defined by a module "
						   "which apache2nginx not supported, you can "
						   "correct or comment it and run again.",
						   NULL);
    }

    for ( ; ml != NULL; ml = ml->next) {
        void *dir_config = ap_set_config_vectors(parms->server,
                                                 section_vector,
                                                 parms->path,
                                                 ml->m,
                                                 parms->pool);
        const char *retval;
        cmd = ml->cmd;

        /* Once was enough? */
        if (cmd->req_override & EXEC_ON_READ) {
            continue;
        }

        /** PARAM_UNCONVERTED is 
         * (PARAM_UNSUPPORTED | PARAM_UNRECOGNIZED | 
         * PARAM_ERROR | PARAM_NEEDLESS_PROCESS)
         */
		if ( parms->flag & PARAM_UNCONVERTED ){
			apn_info("Ignore to execute the directive %s", cmd->name); 
            continue;
		}

        retval = invoke_cmd(cmd, parms, dir_config, current->args);

        /** for some directive, we have not implement yet. */
        if ( !apn_module_is_supported(ml->m) && parms->directive ){
            apn_set_unsupport(parms, MSG_NO_IMPLEMENT);
            apn_debug("module: %s, directive: %s\n", 
                    ml->m->name, current->directive);
        }

        if (retval != NULL && strcmp(retval, DECLINE_CMD) != 0) {
            /* If the directive in error has already been set, don't
             * replace it.  Otherwise, an error inside a container
             * will be reported as occuring on the first line of the
             * container.
             */
            if (!parms->err_directive) {
                parms->err_directive = current;
            }
            return retval;
        }
    }

    return NULL;
}

AP_DECLARE(const char *) ap_walk_config(ap_directive_t *current,
                                        cmd_parms *parms,
                                        ap_conf_vector_t *section_vector)
{
    ap_conf_vector_t *oldconfig = parms->context;

    parms->context = section_vector;

    /* scan through all directives, executing each one */
    for (; current != NULL; current = current->next) {
        const char *errmsg;

        parms->directive = current;
		parms->flag = current->flag; 

        /* actually parse the command and execute the correct function */
        errmsg = ap_walk_config_sub(current, parms, section_vector);
        if (errmsg != NULL) {
            /* restore the context (just in case) */
            if( parms->flag & PARAM_UNRECOGNIZED ){
                current->flag = parms->flag;
            } else {
                current->flag = PARAM_ERROR;
            }
			current->errmsg = errmsg;
        }
    }

    parms->context = oldconfig;
    return NULL;
}

static apn_local_conf_t* apn_get_local_conf(apr_pool_t *p)
{
    if (!apn_local_conf){
        apn_local_conf = apr_palloc(p, sizeof(apn_local_conf_t));
        apn_local_conf->user = 0;
        apn_local_conf->group = 0;
        apn_local_conf->server_root = 0;
        apn_local_conf->document_root = 0;
        apn_local_conf->hostname = 0;
    }
    return apn_local_conf;
}

AP_DECLARE(const char *) ap_build_config(cmd_parms *parms,
                                         apr_pool_t *p, apr_pool_t *temp_pool,
                                         ap_directive_t **conftree)
{
    ap_directive_t *current = *conftree;
    ap_directive_t *curr_parent = NULL;
    char *l = apr_palloc (temp_pool, MAX_STRING_LEN);
    const char *errmsg;

    if (current != NULL) {
        while (current->next) {
            current = current->next;
        }
    }

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, parms->config_file))) {
        errmsg = ap_build_config_sub(p, temp_pool, l, parms,
                                     &current, &curr_parent, conftree);
        if (errmsg != NULL)
            return errmsg;

        if (*conftree == NULL && curr_parent != NULL) {
            *conftree = curr_parent;
        }

        if (*conftree == NULL && current != NULL) {
            *conftree = current;
        }
    }

    if (curr_parent != NULL) {
        errmsg = "";

        while (curr_parent != NULL) {
            errmsg = apr_psprintf(p, "%s%s%s:%u: %s> was not closed.",
                                  errmsg,
                                  *errmsg == '\0' ? "" : APR_EOL_STR,
                                  curr_parent->filename,
                                  curr_parent->line_num,
                                  curr_parent->directive);

            parms->err_directive = curr_parent;
            curr_parent = curr_parent->parent;
        }

        return errmsg;
    }

    return NULL;
}

/*
 * Generic command functions...
 */

AP_DECLARE_NONSTD(const char *) ap_set_string_slot(cmd_parms *cmd,
                                                   void *struct_ptr,
                                                   const char *arg)
{
    int offset = (int)(long)cmd->info;

    *(const char **)((char *)struct_ptr + offset) = arg;

    return NULL;
}

AP_DECLARE_NONSTD(const char *) ap_set_int_slot(cmd_parms *cmd,
                                                void *struct_ptr,
                                                const char *arg)
{
#ifndef APACHE2NGINX
    char *endptr;
    char *error_str = NULL;
    int offset = (int)(long)cmd->info;

    *(int *)((char*)struct_ptr + offset) = strtol(arg, &endptr, 10);

    if ((*arg == '\0') || (*endptr != '\0')) {
        error_str = apr_psprintf(cmd->pool,
                     "Invalid value for directive %s, expected integer",
                     cmd->directive->directive);
    }

    return error_str;
#else
    return NULL;
#endif
}

AP_DECLARE_NONSTD(const char *) ap_set_string_slot_lower(cmd_parms *cmd,
                                                         void *struct_ptr,
                                                         const char *arg_)
{
    char *arg = apr_pstrdup(cmd->pool,arg_);
    int offset = (int)(long)cmd->info;

    ap_str_tolower(arg);
    *(char **)((char *)struct_ptr + offset) = arg;

    return NULL;
}

AP_DECLARE_NONSTD(const char *) ap_set_flag_slot(cmd_parms *cmd,
                                                 void *struct_ptr_v, int arg)
{
    int offset = (int)(long)cmd->info;
    char *struct_ptr = (char *)struct_ptr_v;

    *(int *)(struct_ptr + offset) = arg ? 1 : 0;

    return NULL;
}

AP_DECLARE_NONSTD(const char *) ap_set_file_slot(cmd_parms *cmd, void *struct_ptr,
                                                 const char *arg)
{
    /* Prepend server_root to relative arg.
     * This allows most args to be independent of server_root,
     * so the server can be moved or mirrored with less pain.
     */
    const char *path;
    int offset = (int)(long)cmd->info;

    path = ap_server_root_relative(cmd->pool, arg);

    if (!path) {
        return apr_pstrcat(cmd->pool, "Invalid file path ",
                           arg, NULL);
    }

    *(const char **) ((char*)struct_ptr + offset) = path;
    return NULL;
}

AP_DECLARE_NONSTD(const char *) ap_set_deprecated(cmd_parms *cmd,
                                                  void *struct_ptr,
                                                  const char *arg)
{
    return cmd->cmd->errmsg;
}

/*****************************************************************
 *
 * Reading whole config files...
 */

static cmd_parms default_parms =
{NULL, 0, -1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

AP_DECLARE(char *) ap_server_root_relative(apr_pool_t *p, const char *file)
{
    char *newpath = NULL;
    apr_status_t rv;
    rv = apr_filepath_merge(&newpath, ap_server_root, file,
                            APR_FILEPATH_TRUENAME, p);
    if (newpath && (rv == APR_SUCCESS || APR_STATUS_IS_EPATHWILD(rv)
                                      || APR_STATUS_IS_ENOENT(rv)
                                      || APR_STATUS_IS_ENOTDIR(rv))) {
        return newpath;
    }
    else {
        return NULL;
    }
}

AP_DECLARE(const char *) ap_soak_end_container(cmd_parms *cmd, char *directive)
{
    char l[MAX_STRING_LEN];
    const char *args;
    char *cmd_name;

    while(!(ap_cfg_getline(l, MAX_STRING_LEN, cmd->config_file))) {
#if RESOLVE_ENV_PER_TOKEN
        args = l;
#else
        args = ap_resolve_env(cmd->temp_pool, l);
#endif

        cmd_name = ap_getword_conf(cmd->pool, &args);
        if (cmd_name[0] == '<') {
            if (cmd_name[1] == '/') {
                cmd_name[strlen(cmd_name) - 1] = '\0';

                if (strcasecmp(cmd_name + 2, directive + 1) != 0) {
                    return apr_pstrcat(cmd->pool, "Expected </",
                                       directive + 1, "> but saw ",
                                       cmd_name, ">", NULL);
                }

                return NULL; /* found end of container */
            }
            else {
                const char *msg;

                if (*args == '\0' && cmd_name[strlen(cmd_name) - 1] == '>') {
                    cmd_name[strlen(cmd_name) - 1] = '\0';
                }

                if ((msg = ap_soak_end_container(cmd, cmd_name)) != NULL) {
                    return msg;
                }
            }
        }
    }

    return apr_pstrcat(cmd->pool, "Expected </",
                       directive + 1, "> before end of configuration",
                       NULL);
}

static const char *execute_now(char *cmd_line, const char *args,
                               cmd_parms *parms,
                               apr_pool_t *p, apr_pool_t *ptemp,
                               ap_directive_t **sub_tree,
                               ap_directive_t *parent)
{
    /** Here, only 2 cases to need process */
    unsigned int flag = parms->flag;
    if ( flag & PARAM_NEEDLESS_PROCESS){
		return MSG_NEEDLESS_PROCESS;
	}else if ( flag & PARAM_UNRECOGNIZED){
		return MSG_UNRECOGNIZED_MODULE;
    }

    const command_rec *cmd;
    ap_mod_list *ml;
    char *dir = apr_pstrdup(parms->pool, cmd_line);

    ap_str_tolower(dir);

    ml = apr_hash_get(ap_config_hash, dir, APR_HASH_KEY_STRING);

    if (ml == NULL) {
        return apr_pstrcat(parms->pool, "Invalid command '",
                           cmd_line,
                           "', perhaps misspelled or defined by a module "
                           "not included in the server configuration",
                           NULL);
    }

    for ( ; ml != NULL; ml = ml->next) {
        const char *retval;
        cmd = ml->cmd;

        retval = invoke_cmd(cmd, parms, sub_tree, args);

        if (retval != NULL) {
            return retval;
        }
    }

    return NULL;
}

/* This structure and the following functions are needed for the
 * table-based config file reading. They are passed to the
 * cfg_open_custom() routine.
 */

/* Structure to be passed to cfg_open_custom(): it contains an
 * index which is incremented from 0 to nelts on each call to
 * cfg_getline() (which in turn calls arr_elts_getstr())
 * and an apr_array_header_t pointer for the string array.
 */
typedef struct {
    apr_array_header_t *array;
    int curr_idx;
} arr_elts_param_t;


/* arr_elts_getstr() returns the next line from the string array. */
static void *arr_elts_getstr(void *buf, size_t bufsiz, void *param)
{
    arr_elts_param_t *arr_param = (arr_elts_param_t *)param;

    /* End of array reached? */
    if (++arr_param->curr_idx > arr_param->array->nelts)
        return NULL;

    /* return the line */
    apr_cpystrn(buf,
                ((char **)arr_param->array->elts)[arr_param->curr_idx - 1],
                bufsiz);

    return buf;
}


/* arr_elts_close(): dummy close routine (makes sure no more lines can be read) */
static int arr_elts_close(void *param)
{
    arr_elts_param_t *arr_param = (arr_elts_param_t *)param;

    arr_param->curr_idx = arr_param->array->nelts;

    return 0;
}

static const char *process_command_config(server_rec *s,
                                          apr_array_header_t *arr,
                                          ap_directive_t **conftree,
                                          apr_pool_t *p,
                                          apr_pool_t *ptemp)
{
    const char *errmsg;
    cmd_parms parms;
    arr_elts_param_t arr_parms;

    arr_parms.curr_idx = 0;
    arr_parms.array = arr;

    if (ap_config_hash == NULL) {
        rebuild_conf_hash(s->process->pconf, 1);
    }

    parms = default_parms;
    parms.pool = p;
    parms.temp_pool = ptemp;
    parms.server = s;
    parms.override = (RSRC_CONF | OR_ALL) & ~(OR_AUTHCFG | OR_LIMIT);
    parms.override_opts = OPT_ALL | OPT_SYM_OWNER | OPT_MULTI;

    parms.config_file = ap_pcfg_open_custom(p, "-c/-C directives",
                                            &arr_parms, NULL,
                                            arr_elts_getstr, arr_elts_close);

    parms.local_conf = apn_get_local_conf(p);

    errmsg = ap_build_config(&parms, p, ptemp, conftree);
    ap_cfg_closefile(parms.config_file);

    if (errmsg) {
        return apr_pstrcat(p, "Syntax error in -C/-c directive: ", errmsg,
                           NULL);
    }

    return NULL;
}

typedef struct {
    char *fname;
} fnames;

static int fname_alphasort(const void *fn1, const void *fn2)
{
    const fnames *f1 = fn1;
    const fnames *f2 = fn2;

    return strcmp(f1->fname,f2->fname);
}

static const char *process_resource_config_nofnmatch(server_rec *s,
                                                     const char *fname,
                                                     ap_directive_t **conftree,
                                                     apr_pool_t *p,
                                                     apr_pool_t *ptemp,
                                                     unsigned depth)
{
    cmd_parms parms;
    ap_configfile_t *cfp;
    const char *error;
    apr_status_t rv;

    if (ap_is_directory(p, fname)) {
        apr_dir_t *dirp;
        apr_finfo_t dirent;
        int current;
        apr_array_header_t *candidates = NULL;
        fnames *fnew;
        char *path = apr_pstrdup(p, fname);

        if (++depth > AP_MAX_INCLUDE_DIR_DEPTH) {
            return apr_psprintf(p, "Directory %s exceeds the maximum include "
                                "directory nesting level of %u. You have "
                                "probably a recursion somewhere.", path,
                                AP_MAX_INCLUDE_DIR_DEPTH);
        }

        /*
         * first course of business is to grok all the directory
         * entries here and store 'em away. Recall we need full pathnames
         * for this.
         */
        rv = apr_dir_open(&dirp, path, p);
        if (rv != APR_SUCCESS) {
            char errmsg[120];
            return apr_psprintf(p, "Could not open config directory %s: %s",
                                path, apr_strerror(rv, errmsg, sizeof errmsg));
        }

        candidates = apr_array_make(p, 1, sizeof(fnames));
        while (apr_dir_read(&dirent, APR_FINFO_DIRENT, dirp) == APR_SUCCESS) {
            /* strip out '.' and '..' */
            if (strcmp(dirent.name, ".")
                && strcmp(dirent.name, "..")) {
                fnew = (fnames *) apr_array_push(candidates);
                fnew->fname = ap_make_full_path(p, path, dirent.name);
            }
        }

        apr_dir_close(dirp);
        if (candidates->nelts != 0) {
            qsort((void *) candidates->elts, candidates->nelts,
                  sizeof(fnames), fname_alphasort);

            /*
             * Now recurse these... we handle errors and subdirectories
             * via the recursion, which is nice
             */
            for (current = 0; current < candidates->nelts; ++current) {
                fnew = &((fnames *) candidates->elts)[current];
                error = process_resource_config_nofnmatch(s, fnew->fname,
                                                          conftree, p, ptemp,
                                                          depth);
                if (error) {
                    return error;
                }
            }
        }

        return NULL;
    }

    /* GCC's initialization extensions are soooo nice here... */
    parms = default_parms;
    parms.pool = p;
    parms.temp_pool = ptemp;
    parms.server = s;
    parms.override = (RSRC_CONF | OR_ALL) & ~(OR_AUTHCFG | OR_LIMIT);
    parms.override_opts = OPT_ALL | OPT_SYM_OWNER | OPT_MULTI;

    rv = ap_pcfg_openfile(&cfp, p, fname);
    if (rv != APR_SUCCESS) {
        char errmsg[120];
        return apr_psprintf(p, "Could not open configuration file %s: %s",
                            fname, apr_strerror(rv, errmsg, sizeof errmsg));
    }

    parms.local_conf = apn_get_local_conf(p);

    parms.config_file = cfp;
    error = ap_build_config(&parms, p, ptemp, conftree);
    ap_cfg_closefile(cfp);

    if (error) {
        return apr_psprintf(p, "Syntax error on line %d of %s: %s",
                            parms.err_directive->line_num,
                            parms.err_directive->filename, error);
    }

    return NULL;
}

AP_DECLARE(const char *) ap_process_resource_config(server_rec *s,
                                                    const char *fname,
                                                    ap_directive_t **conftree,
                                                    apr_pool_t *p,
                                                    apr_pool_t *ptemp)
{
    /* XXX: lstat() won't work on the wildcard pattern...
     */
#ifndef APACHE2NGINX
    char *newpath = ap_server_root_relative(p, SERVER_CONFIG_FILE);
    /* don't require conf/httpd.conf if we have a -C or -c switch */
    if ((ap_server_pre_read_config->nelts
        || ap_server_post_read_config->nelts)
        && (newpath != NULL && !(strcmp(fname, newpath)))
		) {
        apr_finfo_t finfo;

        if (apr_stat(&finfo, fname, APR_FINFO_LINK | APR_FINFO_TYPE, p) != APR_SUCCESS)
            return NULL;
    }
#endif

    if (!apr_fnmatch_test(fname)) {
        return process_resource_config_nofnmatch(s, fname, conftree, p, ptemp,
                                                 0);
    } else {
        apr_dir_t *dirp;
        apr_finfo_t dirent;
        int current;
        apr_array_header_t *candidates = NULL;
        fnames *fnew;
        apr_status_t rv;
        char *path = apr_pstrdup(p, fname), *pattern = NULL;

        pattern = ap_strrchr(path, '/');

        AP_DEBUG_ASSERT(pattern != NULL); /* path must be absolute. */

        *pattern++ = '\0';

        if (apr_fnmatch_test(path)) {
            return apr_pstrcat(p, "Wildcard patterns not allowed in Include ",
                               fname, NULL);
        }

        if (!ap_is_directory(p, path)){
            return apr_pstrcat(p, "Include directory '", path, "' not found",
                               NULL);
        }

        if (!apr_fnmatch_test(pattern)) {
            return apr_pstrcat(p, "Must include a wildcard pattern for "
                               "Include ", fname, NULL);
        }

        /*
         * first course of business is to grok all the directory
         * entries here and store 'em away. Recall we need full pathnames
         * for this.
         */
        rv = apr_dir_open(&dirp, path, p);
        if (rv != APR_SUCCESS) {
            char errmsg[120];
            return apr_psprintf(p, "Could not open config directory %s: %s",
                                path, apr_strerror(rv, errmsg, sizeof errmsg));
        }

        candidates = apr_array_make(p, 1, sizeof(fnames));
        while (apr_dir_read(&dirent, APR_FINFO_DIRENT, dirp) == APR_SUCCESS) {
            /* strip out '.' and '..' */
            if (strcmp(dirent.name, ".")
                && strcmp(dirent.name, "..")
                && (apr_fnmatch(pattern, dirent.name,
                                APR_FNM_PERIOD) == APR_SUCCESS)) {
                fnew = (fnames *) apr_array_push(candidates);
                fnew->fname = ap_make_full_path(p, path, dirent.name);
            }
        }

        apr_dir_close(dirp);
        if (candidates->nelts != 0) {
            const char *error;

            qsort((void *) candidates->elts, candidates->nelts,
                  sizeof(fnames), fname_alphasort);

            /*
             * Now recurse these... we handle errors and subdirectories
             * via the recursion, which is nice
             */
            for (current = 0; current < candidates->nelts; ++current) {
                fnew = &((fnames *) candidates->elts)[current];
                error = process_resource_config_nofnmatch(s, fnew->fname,
                                                          conftree, p,
                                                          ptemp, 0);
                if (error) {
                    return error;
                }
            }
        }
    }

    return NULL;
}

/*
 * It is a strategy to decide it.
 */
static int calculate_if_local_conf( apn_local_conf_t* conf )
{
    if ( conf->user &&
         conf->group &&
         conf->server_root ){
        return 1;
    }

    /*
    conf->document_root;
    conf->hostname;
    */

    return 0;
}

AP_DECLARE(int) ap_process_config_tree(server_rec *s,
                                       ap_directive_t *conftree,
                                       apr_pool_t *p,
                                       apr_pool_t *ptemp)
{
    const char *errmsg;
    cmd_parms parms;

    parms = default_parms;
    parms.pool = p;
    parms.temp_pool = ptemp;
    parms.server = s;
    parms.override = (RSRC_CONF | OR_ALL) & ~(OR_AUTHCFG | OR_LIMIT);
    parms.override_opts = OPT_ALL | OPT_SYM_OWNER | OPT_MULTI;
    parms.limited = -1;

    parms.local_conf = apn_get_local_conf(p);

    errmsg = ap_walk_config(conftree, &parms, s->lookup_defaults);
    if (errmsg) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, p,
                     "Syntax error on line %d of %s:",
                     parms.err_directive->line_num,
                     parms.err_directive->filename);
        ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, p,
                     "%s", errmsg);
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apn_is_local_conf = calculate_if_local_conf( apn_local_conf );

    return OK;
}

AP_CORE_DECLARE(int) ap_parse_htaccess(ap_conf_vector_t **result,
                                       request_rec *r, int override,
                                       int override_opts,
                                       const char *d, const char *access_name)
{
#ifndef APACHE2NGINX
    ap_configfile_t *f = NULL;
    cmd_parms parms;
    char *filename = NULL;
    const struct htaccess_result *cache;
    struct htaccess_result *new;
    ap_conf_vector_t *dc = NULL;
    apr_status_t status;

    /* firstly, search cache */
    for (cache = r->htaccess; cache != NULL; cache = cache->next) {
        if (cache->override == override && strcmp(cache->dir, d) == 0) {
            *result = cache->htaccess;
            return OK;
        }
    }

    parms = default_parms;
    parms.override = override;
    parms.override_opts = override_opts;
    parms.pool = r->pool;
    parms.temp_pool = r->pool;
    parms.server = r->server;
    parms.path = apr_pstrdup(r->pool, d);
	parms.flag = PARAM_UNDEFINE;

    /* loop through the access names and find the first one */
    while (access_name[0]) {
        /* AFAICT; there is no use of the actual 'filename' against
         * any canonicalization, so we will simply take the given
         * name, ignoring case sensitivity and aliases
         */
        filename = ap_make_full_path(r->pool, d,
                                     ap_getword_conf(r->pool, &access_name));
        status = ap_pcfg_openfile(&f, r->pool, filename);

        if (status == APR_SUCCESS) {
            const char *errmsg;
            ap_directive_t *temptree = NULL;

            dc = ap_create_per_dir_config(r->pool);

            parms.config_file = f;
            errmsg = ap_build_config(&parms, r->pool, r->pool, &temptree);
            if (errmsg == NULL)
                errmsg = ap_walk_config(temptree, &parms, dc);

            ap_cfg_closefile(f);

            if (errmsg) {
                ap_log_rerror(APLOG_MARK, APLOG_ALERT, 0, r,
                              "%s: %s", filename, errmsg);
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            *result = dc;
            break;
        }
        else {
            if (!APR_STATUS_IS_ENOENT(status)
                && !APR_STATUS_IS_ENOTDIR(status)) {
                ap_log_rerror(APLOG_MARK, APLOG_CRIT, status, r,
                              "%s pcfg_openfile: unable to check htaccess file, "
                              "ensure it is readable",
                              filename);
                apr_table_setn(r->notes, "error-notes",
                               "Server unable to read htaccess file, denying "
                               "access to be safe");
                return HTTP_FORBIDDEN;
            }
        }
    }

    /* cache it */
    new = apr_palloc(r->pool, sizeof(struct htaccess_result));
    new->dir = parms.path;
    new->override = override;
    new->override_opts = override_opts;
    new->htaccess = dc;

    /* add to head of list */
    new->next = r->htaccess;
    r->htaccess = new;

    return OK;
#else
    return 0;
#endif /* APACHE2NGINX */
}

AP_CORE_DECLARE(const char *) ap_init_virtual_host(apr_pool_t *p,
                                                   const char *hostname,
                                                   server_rec *main_server,
                                                   server_rec **ps)
{
    server_rec *s = (server_rec *) apr_pcalloc(p, sizeof(server_rec));

    /* TODO: this crap belongs in http_core */
    s->process = main_server->process;
    s->server_admin = NULL;
    s->server_hostname = NULL;
    s->server_scheme = NULL;
	s->error_fname = NULL;

    s->timeout = 0;
    s->keep_alive_timeout = 0;
    s->keep_alive = -1;
    s->keep_alive_max = -1;
    s->error_log = main_server->error_log;
    s->loglevel = main_server->loglevel;
    /* useful default, otherwise we get a port of 0 on redirects */
    s->port = main_server->port;
    s->next = NULL;

    s->is_virtual = 1;
    s->names = apr_array_make(p, 4, sizeof(char **));
    s->wild_names = apr_array_make(p, 4, sizeof(char **));

    s->module_config = create_empty_config(p);
    s->lookup_defaults = ap_create_per_dir_config(p);

    s->limit_req_line = main_server->limit_req_line;
    s->limit_req_fieldsize = main_server->limit_req_fieldsize;
    s->limit_req_fields = main_server->limit_req_fields;
    s->ap_document_root = NULL;

    *ps = s;

    return ap_parse_vhost_addrs(p, hostname, s);
}


/**
 * By the function, the order of some directives is insignificant.
 * @Reed 2012/06/15
 */
AP_DECLARE(void) ap_fixup_virtual_hosts(apr_pool_t *p, server_rec *main_server)
{
    server_rec *virt;

    for (virt = main_server->next; virt; virt = virt->next) {
        merge_server_configs(p, main_server->module_config,
                             virt->module_config);

        virt->lookup_defaults =
            ap_merge_per_dir_configs(p, main_server->lookup_defaults,
                                     virt->lookup_defaults);

        if (virt->server_admin == NULL)
            virt->server_admin = main_server->server_admin;

		/** just apache2nginx need */
        if (virt->error_fname == NULL)
            virt->error_fname = main_server->error_fname;

        if (virt->timeout == 0)
            virt->timeout = main_server->timeout;

        if (virt->keep_alive_timeout == 0)
            virt->keep_alive_timeout = main_server->keep_alive_timeout;

        if (virt->keep_alive == -1)
            virt->keep_alive = main_server->keep_alive;

        if (virt->keep_alive_max == -1)
            virt->keep_alive_max = main_server->keep_alive_max;

        /* XXX: this is really something that should be dealt with by a
         * post-config api phase
         */
        ap_core_reorder_directories(p, virt);
    }

    ap_core_reorder_directories(p, main_server);
}

/*****************************************************************
 *
 * Getting *everything* configured...
 */

static void init_config_globals(apr_pool_t *p)
{
    /* Global virtual host hash bucket pointers.  Init to null. */
    ap_init_vhost_config(p);
}

static server_rec *init_server_config(process_rec *process, apr_pool_t *p)
{
    apr_status_t rv;
    server_rec *s = (server_rec *) apr_pcalloc(p, sizeof(server_rec));

    apr_file_open_stderr(&s->error_log, p);
    s->process = process;
    s->port = 0;
    s->server_admin = DEFAULT_ADMIN;
    s->server_hostname = NULL;
    s->server_scheme = NULL;
    s->error_fname = DEFAULT_ERRORLOG;
    s->loglevel = DEFAULT_LOGLEVEL;
    s->limit_req_line = DEFAULT_LIMIT_REQUEST_LINE;
    s->limit_req_fieldsize = DEFAULT_LIMIT_REQUEST_FIELDSIZE;
    s->limit_req_fields = DEFAULT_LIMIT_REQUEST_FIELDS;
    s->timeout = apr_time_from_sec(DEFAULT_TIMEOUT);
    s->keep_alive_timeout = apr_time_from_sec(DEFAULT_KEEPALIVE_TIMEOUT);
    s->keep_alive_max = DEFAULT_KEEPALIVE;
    s->keep_alive = 1;
    s->next = NULL;
    s->addrs = apr_pcalloc(p, sizeof(server_addr_rec));

    /* NOT virtual host; don't match any real network interface */
    rv = apr_sockaddr_info_get(&s->addrs->host_addr,
                               NULL, APR_INET, 0, 0, p);
    ap_assert(rv == APR_SUCCESS); /* otherwise: bug or no storage */

    s->addrs->host_port = 0; /* matches any port */
    s->addrs->virthost = ""; /* must be non-NULL */
    s->names = s->wild_names = NULL;

    s->ap_document_root = DOCUMENT_LOCATION;

    s->module_config = create_server_config(p, s);
    s->lookup_defaults = create_default_per_dir_config(p);

    return s;
}


AP_DECLARE(server_rec*) ap_read_config(process_rec *process, apr_pool_t *ptemp,
                                       const char *filename,
                                       ap_directive_t **conftree)
{
    const char *confname, *error;
    apr_pool_t *p = process->pconf;
    server_rec *s = init_server_config(process, p);

    init_config_globals(p);

    /* All server-wide config files now have the SAME syntax... */
    error = process_command_config(s, ap_server_pre_read_config, conftree,
                                   p, ptemp);
    if (error) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, 0, NULL, "%s: %s",
                     ap_server_argv0, error);
        return NULL;
    }

    /* process_command_config may change the ServerRoot so
     * compute this config file name afterwards.
     */
    /*confname = ap_server_root_relative(p, filename);*/
    confname = filename;

    if (!confname) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT,
                     APR_EBADPATH, NULL, "Invalid config file path %s",
                     filename);
        return NULL;
    }

    error = ap_process_resource_config(s, confname, conftree, p, ptemp);
    if (error) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, 0, NULL,
                     "%s: %s", ap_server_argv0, error);
        return NULL;
    }

    error = process_command_config(s, ap_server_post_read_config, conftree,
                                   p, ptemp);

    if (error) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_CRIT, 0, NULL, "%s: %s",
                     ap_server_argv0, error);
        return NULL;
    }

    return s;
}

AP_DECLARE(void) ap_single_module_configure(apr_pool_t *p, server_rec *s,
                                            module *m)
{
#ifndef APACHE2NGINX
    if (m->create_server_config)
        ap_set_module_config(s->module_config, m,
                             (*m->create_server_config)(p, s));

    if (m->create_dir_config)
        ap_set_module_config(s->lookup_defaults, m,
                             (*m->create_dir_config)(p, NULL));
#endif
}

AP_DECLARE(void) ap_run_rewrite_args(process_rec *process)
{
    module *m;

    for (m = ap_top_module; m; m = m->next) {
        if (m->rewrite_args) {
            (*m->rewrite_args)(process);
        }
    }
}

/********************************************************************
 * Configuration directives are restricted in terms of where they may
 * appear in the main configuration files and/or .htaccess files according
 * to the bitmask req_override in the command_rec structure.
 * If any of the overrides set in req_override are also allowed in the
 * context in which the command is read, then the command is allowed.
 * The context is determined as follows:
 *
 *    inside *.conf --> override = (RSRC_CONF|OR_ALL)&~(OR_AUTHCFG|OR_LIMIT);
 *    within <Directory> or <Location> --> override = OR_ALL|ACCESS_CONF;
 *    within .htaccess --> override = AllowOverride for current directory;
 *
 * the result is, well, a rather confusing set of possibilities for when
 * a particular directive is allowed to be used.  This procedure prints
 * in English where the given (pc) directive can be used.
 */
static void show_overrides(const command_rec *pc, module *pm)
{
    int n = 0;

    printf("\tAllowed in *.conf ");
    if ((pc->req_override & (OR_OPTIONS | OR_FILEINFO | OR_INDEXES))
        || ((pc->req_override & RSRC_CONF)
        && ((pc->req_override & (ACCESS_CONF | OR_AUTHCFG | OR_LIMIT))))) {
        printf("anywhere");
    }
    else if (pc->req_override & RSRC_CONF) {
        printf("only outside <Directory>, <Files> or <Location>");
    }
    else {
        printf("only inside <Directory>, <Files> or <Location>");
    }

    /* Warn if the directive is allowed inside <Directory> or .htaccess
     * but module doesn't support per-dir configuration
     */
    if ((pc->req_override & (OR_ALL | ACCESS_CONF)) && !pm->create_dir_config)
        printf(" [no per-dir config]");

    if (pc->req_override & OR_ALL) {
        printf(" and in .htaccess\n\twhen AllowOverride");

        if ((pc->req_override & OR_ALL) == OR_ALL) {
            printf(" isn't None");
        }
        else {
            printf(" includes ");

            if (pc->req_override & OR_AUTHCFG) {
                if (n++)
                    printf(" or ");

                printf("AuthConfig");
            }

            if (pc->req_override & OR_LIMIT) {
                if (n++)
                    printf(" or ");

                printf("Limit");
            }

            if (pc->req_override & OR_OPTIONS) {
                if (n++)
                    printf(" or ");

                printf("Options");
            }

            if (pc->req_override & OR_FILEINFO) {
                if (n++)
                    printf(" or ");

                printf("FileInfo");
            }

            if (pc->req_override & OR_INDEXES) {
                if (n++)
                    printf(" or ");

                printf("Indexes");
            }
        }
    }

    printf("\n");
}

/* Show the preloaded configuration directives, the help string explaining
 * the directive arguments, in what module they are handled, and in
 * what parts of the configuration they are allowed.  Used for httpd -L.
 */
AP_DECLARE(void) ap_show_directives(void)
{
    const command_rec *pc;
    int n;
    
    module *modp = NULL;
    for (n = 0; ap_loaded_modules[n]; ++n) {
        modp = ap_loaded_modules[n];
        if (apn_module_is_supported(modp)) {
            for (pc = modp->cmds; pc && pc->name; ++pc) {
                printf("%s (%s)\n", pc->name, modp->name);

                if (pc->errmsg)
                    printf("\t%s\n", pc->errmsg);

                show_overrides(pc, modp);
            }
        }
    }
}


/* Show the preloaded module names.  Used for httpd -l. */
AP_DECLARE(void) ap_show_modules(void)
{
    int n;
    module *modp = NULL;
    printf("Supported modules list:\n");
	for (n = 0; ap_loaded_modules[n]; ++n){
		modp = ap_loaded_modules[n];
        if (apn_module_is_supported(modp)){
			printf("  %s\n", modp->name);
        }
	}
}

AP_DECLARE(const char *) ap_show_mpm(void)
{
    return MPM_NAME;
}

//---------------------------------------------------------------
/** about migrate ngx as blow. */


#define NULL_DIRECTIVE {NULL,NULL}
static const char* default_main_directives[][2] = {
    {"worker_processes", "1" },
    {"pid", "logs/nginx.pid" },
    {"events", "{" },
    {"http", "{" },
    NULL_DIRECTIVE
};

static const char* default_events_directives[][2] = {
    {"worker_connections", "1024" },
    NULL_DIRECTIVE
};

static const char* default_http_directives[][2] = {
    {"include", NGX_TYPES_CONFIG_FILE },
    NULL_DIRECTIVE
};


/** These directives could configurate in http fields.
 *  So when the same directive configurate in each virtual host,
 *  we should merge, especially, it is incorrent some directives
 *  configurate each virtual host meanwhile, for example.
 *  logformat, and in this case, we have to do merge.
 */
static const char *mergeable_http_directives[] = {
    "root",
    "index",

    "sendfile",

    "keepalive_disable",
    "keepalive_timeout",
    "keepalive_requests",

    "log_format",
    "access_log",
    "error_log",

    "default_time",
    "error_page",

    "gzip",
    "gzip_buffers",
    "gzip_comp_level",
    "gzip_disable",
    "gzip_http_version",
    "gzip_min_length",
    "gzip_proxied",
    "gzip_types",
    "gzip_vary"
};

/**
 * Statement:
 */

static char* apn_get_errorlog( apr_pool_t *p, 
        const char* error_fname, int loglevel );

static apn_module_t* process_server_config( apr_pool_t *p, server_rec *s);

static int apn_init(apr_pool_t *p, server_rec *s);
static int apn_migration(apr_pool_t *, server_rec *, const char*);
static int apn_merging(apr_pool_t *p);
static int apn_checking(apr_pool_t *p);
static apr_status_t apn_write_nginx_conf_file( apr_pool_t *p, 
        const char* filename );

static int apn_fixup_module_config(apr_pool_t *pool, apn_node_t *s);

static int apn_walk_server_config(apr_pool_t *p, 
        cmd_parms *parms,
        apn_node_t* parent,
        ap_conf_vector_t *section_vector);

/** end of statement. */

static char* apn_get_errorlog( apr_pool_t *p, 
        const char* error_fname, int loglevel )
{
    if (error_fname){
        /*ngx: error_log file [ debug | info | notice | warn | error | crit ]*/
        const char* level = NULL;
        switch (loglevel){
            case LOG_EMERG  :  /* system is unusable */
            case LOG_ALERT  :  /* action must be taken immediately */
            case LOG_CRIT   :  /* critical conditions */
                level = "crit";
                break;
            case LOG_ERR    :  /* error conditions */
                level = "error";
                break;
            case LOG_WARNING:  /* warning conditions */
                level = "warn";
                break;
            case LOG_NOTICE :  /* normal but significant condition */
                level = "notice";
                break;
            case LOG_INFO   :  /* informational */
                level = "info";
                break;
            case LOG_DEBUG  :  /* debug-level messages */
                level = "debug";
                break;
            default:
                break;
        }
        return apr_pstrcat(p, error_fname, " ", level, NULL );
    }

    return NULL;
}



static apn_module_t* process_server_config( apr_pool_t *p, server_rec *s)
{
    apn_module_t* mod = NULL;
    int i;

    /** process server addr */
    int is_virtual = s->is_virtual;
    server_addr_rec *addrs = s->addrs;
    /*apr_port_t port = s->port;*/
    /*const char *server_scheme = s->server_scheme;*/

    char *addr_list = NULL;
    apr_sockaddr_t *host_addr;
    apr_port_t host_port;

    while( addrs ){
        host_addr = addrs->host_addr;
        host_port = addrs->host_port;

        char *virthost = NULL;
        char *port = NULL;

        port = apr_itoa(p, host_port);

        if (is_virtual) {
            virthost = addrs->virthost;
            if (virthost == NULL) {
                virthost = host_addr->hostname;
            }

            if (addrs->host_addr->family == AF_INET) {
                if (virthost && strcmp(virthost, "*") == 0 && host_port != 0) {
                    addr_list = apr_pstrcat( p, port, NULL);
                } else if (virthost && host_port != 0) {
                    addr_list = apr_pstrcat( p, virthost, ":", port, NULL);
                }
            } else {
                if (virthost && host_port != 0) {
                    addr_list = apr_pstrcat( p, "[", virthost, "]:", port, NULL);
                }
            }

        } else {
            if(host_port != 0){
                addr_list = apr_pstrcat( p, apr_itoa(p, host_port), NULL);
            }
        }

        if (addr_list){
            mod = apn_mod_insert_sibling(mod, "listen", addr_list);
        } else {
            ap_listen_rec *walk;
            ap_listen_rec *old_listeners = ap_listeners;

            for (walk = old_listeners; walk;) {
                if ((walk->listen_args != NULL) && strcmp(walk->listen_args, "") != 0 ) { 
                    mod = apn_mod_insert_sibling(mod, "listen", walk->listen_args);
                }

                walk = walk->next;
            }
        }

        addrs = addrs->next;
    }

    /** process host name */
    char *server_hostname = s->server_hostname;
    apr_array_header_t *names = s->names;
    apr_array_header_t *wild_names = s->wild_names;
    if (names) {
        char **name = (char **)names->elts;
        for (i = 0; i < names->nelts; ++i) {
            if (!name[i])
                continue;
            server_hostname = 
                apr_pstrcat(p, server_hostname, " ", name[i], NULL );
        }
    }

    if (wild_names) {
        char **name = (char **)wild_names->elts;
        for (i = 0; i < wild_names->nelts; ++i) {
            if (!name[i])
                continue;
            server_hostname = 
                apr_pstrcat(p, server_hostname, " ", name[i], NULL );
        }
    }

    if (server_hostname){
        mod = apn_mod_insert_sibling(mod, "server_name", server_hostname);
    }

    /** process error log */
	/**
	 * if error_fname is not config in vhost, 
	 * we should use of the main server
	 */
    char *error_fname = s->error_fname;
    /*apr_file_t *error_log = s->error_log;*/
    int loglevel = s->loglevel;
    if (error_fname){
        error_fname = apn_get_errorlog( p, error_fname, loglevel );
        mod = apn_mod_insert_sibling(mod, "error_log", error_fname);
    }

    /** process keepalive */
    apr_interval_time_t keep_alive_timeout = 
                                apr_time_sec(s->keep_alive_timeout);
    int keep_alive_max = s->keep_alive_max;
    int keep_alive = s->keep_alive;
    if (keep_alive){
        mod = apn_mod_insert_sibling(mod, 
                "keepalive_timeout", apr_itoa(p, keep_alive_timeout));
        mod = apn_mod_insert_sibling(mod, 
                "keepalive_requests", apr_itoa(p, keep_alive_max));
    }else{
        /** The default values in nginx. */
        mod = apn_mod_insert_sibling(mod, "keepalive_timeout", "0");
        mod = apn_mod_insert_sibling(mod, "keepalive_requests", "100");
    }

    /** The apr interval we will wait for another request */
    /** Maximum requests per connection */
    /** Use persistent connections? */

    /** limit on size of the HTTP request line    */
    /*int limit_req_line = s->limit_req_line;*/
    /** limit on size of any request header field */
    /*int limit_req_fieldsize = s->limit_req_fieldsize;*/
    /** limit on number of request header fields  */
    /*int limit_req_fields = s->limit_req_fields; */

    /** Timeout, as an apr interval, before we give up */
    if(s->timeout != apr_time_from_sec(DEFAULT_TIMEOUT)){
        mod = apn_mod_insert_sibling(mod, 
                "client_header_timeout", 
                apr_itoa(p, apr_time_sec(s->timeout)));
        mod = apn_mod_insert_sibling(mod, 
                "client_body_timeout", 
                apr_itoa(p, apr_time_sec(s->timeout)));
    }

    /*
    const char *path = s->path;
    int pathlen = s->pathlen;

    const char *defn_name = s->defn_name;
    unsigned defn_line_number = s->defn_line_number;
    char *server_admin = s->server_admin;
    */

    return mod;
}


static int apn_walk_server_config(apr_pool_t *p, 
        cmd_parms *parms,
        apn_node_t* parent,
        ap_conf_vector_t *section_vector)
{
    apn_module_t *apn_modp_list;
    apn_convert_server_config_func func;
    module *modp;
    int n;

    for (n = 0; ap_loaded_modules[n]; ++n){
        modp = ap_loaded_modules[n];
        func = modp->apn_convert_server_config;

        if (func){
            apn_modp_list = (*func)(p, parms, section_vector);

            while(apn_modp_list){

                parent = apn_insert_subtree(parent, 
                                    apn_modp_list->directives);

                if ( !parent ){
                    apn_error("build module failure!\n");
                    return APR_EGENERAL;
                }
                apn_modp_list = apn_modp_list->next;
            }
        }
    }

    return APR_SUCCESS;
}

#define ONE_MINUTE (60)
#define ONE_HOUR (ONE_MINUTE*ONE_MINUTE)
#define ONE_DAY (ONE_HOUR*24)

/*
 * convert the apr_time_t to string which nginx supported.
 * 86400s --> 1d(ay)
 * 90061s --> 1d1h1m1s.
 * it is usefull as following directive.
 * ExpiresDefault "access plus 1 day 1 hour 1 minute 1 second" 
 *										--> expires +1d1h1m1s
 */
APR_DECLARE(apr_status_t) apn_time_to_string(apr_pool_t* p,
		char **timestr, 
		apr_time_t second)
{
	if(!p ) return APR_EGENERAL;

	int d = second / ONE_DAY;
	*timestr = NULL;

	if(d > 0) {
		second = second - d * ONE_DAY;
		*timestr = apr_pstrcat(p, apr_itoa(p, d), "d", NULL);
	}

	int h = second / ONE_HOUR;
	if(h > 0) {
		second = second - h*ONE_HOUR;
		*timestr = apr_pstrcat(p, *timestr, apr_itoa(p, h), "h", NULL);
	}

	int m = second / ONE_MINUTE;
	if(m > 0) {
		second = second - m*ONE_MINUTE;
		*timestr = apr_pstrcat(p, *timestr, apr_itoa(p, m), "m", NULL);
	}
	if(second > 0) {
		*timestr = apr_pstrcat(p, *timestr, apr_itoa(p, second), "s", NULL);
	}else if (*timestr == NULL){
		*timestr = apr_pstrcat(p, "0s", NULL);
	}

	return APR_SUCCESS;
}

AP_DECLARE(int) apn_walk_dir_config(apr_pool_t *p, 
        cmd_parms *parms,
        apn_node_t* parent,
        ap_conf_vector_t *section_vector)
{
    apn_module_t *apn_modp_list;
    apn_convert_dir_config_func func;
    module *modp;
    int n;
    
    for (n = 0; ap_loaded_modules[n]; ++n){
        modp = ap_loaded_modules[n];
        func = modp->apn_convert_dir_config;

        if (func){
            apn_modp_list = (*func)(p, parms, section_vector);

            while(apn_modp_list){

                parent = apn_insert_subtree(parent, 
                                    apn_modp_list->directives);

                if ( !parent ){
                    apn_error("build module failure!\n");
                    return APR_EGENERAL;
                }
                apn_modp_list = apn_modp_list->next;
            }
        }
    }

    return APR_SUCCESS;
}

static int apn_fixup_module_config(apr_pool_t *pool, apn_node_t *s)
{
    apr_array_header_t *directives 
        = apr_array_make(pool, 1, sizeof(apn_node_t*));

    apn_node_t *p = s;
    apn_node_t *subtree, *new_pos, *pnext;
    apn_node_t **new;
    while(p){
        subtree = p;
        if( subtree->need_fixup){
            new_pos = subtree->parent;
            pnext = subtree->next;
            subtree->need_fixup = 0;
            subtree = apn_remove_subtree(subtree);
            if (!subtree){
                apn_error("fixup failed when remove subtree.");
                return APR_EGENERAL;
            }
            subtree = apn_insert_as_next(new_pos, subtree);
            if (!subtree){
                apn_error("fixup failed when insert subtree.");
                return APR_EGENERAL;
            }

            p = pnext;
            if (!p) {
                new = (apn_node_t**)apr_array_pop(directives);
                if(new) p = *new;
            }
            continue;
        }
        if ( p->first_child ) {
            if( p->next ) {
                *(apn_node_t**)apr_array_push(directives) = p->next;
            }
            p = p->first_child;
        }else{
            p = p->next;
            if (!p) {
                new = (apn_node_t**)apr_array_pop(directives);
                if(new) p = *new;
            }
        }
    }

    return APR_SUCCESS;
}


static context_per_dir_config* init_dir_context( apr_pool_t *p)
{
    context_per_dir_config* conf 
        = apr_palloc(p, sizeof(context_per_dir_config));

    conf->add_default_charset_name = DEFAULT_ADD_DEFAULT_CHARSET_NAME;

    /* Overriding all negotiation
     */
    conf->output_filters = NULL;
    conf->input_filters = NULL;
    conf->ct_output_filters = NULL;

    conf->ap_auth_name = NULL;
    conf->ap_auth_type = NULL;
    conf->ap_default_type = NULL;
    conf->ap_requires = NULL;

    return conf;
}

static int apn_migration(apr_pool_t *p, server_rec *s, 
		const char* ngx_confname)
{
    if ( !p || !s ){
        // p and s are need to initialized.
        apn_error("p or s is null.\n");
        return APR_EINIT;
    }

    server_rec *main_server = s;
    apn_server_t *apn_server = apn_server_list;
    int rv;
    apn_module_t *mod = NULL;

    cmd_parms parms;
    parms = default_parms;
    parms.pool = p;
    parms.temp_pool = p;

	/** remember the ngx conf file */
    ap_configfile_t *f = apr_palloc(p, sizeof(ap_configfile_t));
	/*f->getch = f->getstr = f->close = f->param = NULL;*/
	f->name = ngx_confname;
	parms.config_file = f;

    parms.override = (RSRC_CONF | OR_ALL) & ~(OR_AUTHCFG | OR_LIMIT);
    parms.override_opts = OPT_ALL | OPT_SYM_OWNER | OPT_MULTI;
    parms.limited = -1;

    parms.local_conf = apn_local_conf;
    parms.is_local_conf = apn_is_local_conf;

    parms.path = NULL;
    parms.real_fake_rec = NULL;

    parms.dir_context = init_dir_context(p);

    for (s = main_server; s; s = s->next) {

        if(!apn_server) {
            apn_error("apn_server is null.\n");
            break;
        }

        /**
         * if have virtual hosts, we ignore the main server.
         */
        if(main_server->next && !s->is_virtual) continue;    

        /** process server record */
        mod = process_server_config(p, s);
        if (!apn_insert_subtree(apn_server->server, mod->directives)){
            apn_error("build module failure!\n");
            return APR_EGENERAL;
        }

        parms.server = s;

        /** process per-dir vector */
        rv = apn_walk_dir_config(p, &parms, apn_server->server, 
                                            s->lookup_defaults);
        if ( rv != APR_SUCCESS ){
            apn_error("build module failure!\n");
            return rv;
        }

        /** process per-server vector */
        rv = apn_walk_server_config(p, &parms, apn_server->server, 
                                            s->module_config);
        if ( rv != APR_SUCCESS ){
            apn_error("build module failure!\n");
            return rv;
        }

        /** there are directives is not in position. fix up. */
        rv = apn_fixup_module_config(p, apn_server->server);
        if ( rv != APR_SUCCESS ){
            apn_error("build module failure!\n");
            return rv;
        }

        apn_server = apn_server->next;

    }

    return APR_SUCCESS;
}


/** 
 * merging the redundance directives.
 * @param p
 */
static int apn_merging(apr_pool_t *p)
{
    int i, j, rv;
    int need_merge;
    apn_server_t *apn_server;
    apr_array_header_t *directives = NULL;
    apr_array_header_t *founds_1st_server = NULL;
    const char* directive = NULL;
    apn_node_t *base_node = NULL;
    apn_node_t *coming_node;
    apn_node_t **new;

    directives = apr_array_make(p, 1, sizeof(apn_node_t*));
    
    int n = sizeof(mergeable_http_directives)/sizeof(const char*);
    for(i = 0; i < n; i++) {
        /** prepare a directive */
        directive = mergeable_http_directives[i];

        /** find the same direcives in the first server. */
        founds_1st_server = NULL;
        apn_server = apn_server_list;
        if( !apn_server || !(apn_server->server)) {
            apn_error("apn server is not built.\n");
            return APR_EINIT;
        }
        founds_1st_server = apn_find_children(apn_server->server, directive, NULL);
        if (!founds_1st_server || apr_is_empty_array(founds_1st_server) ) continue;

        /** finding and merging... */
        apn_node_t **node_array = (apn_node_t **)founds_1st_server->elts;
        for (j = 0; j < founds_1st_server->nelts; ++j) {
            base_node = node_array[j];

            /** look up and get directive from other servers.*/
            apn_server = apn_server_list->next;
            apr_array_clear( directives);
            need_merge = 1;
            while(base_node && apn_server){

                apn_node_t *parent = apn_server->server;
                coming_node = apn_find_child(parent, 
                            base_node->directive, base_node->args);
                if(!coming_node){
                    need_merge = 0;
                    break;
                }

                new = (apn_node_t**)apr_array_push(directives);
                *new = coming_node;
                apn_server= apn_server->next;
            }
            if(!need_merge) continue;

            /** delete others */
            while( directives && !apr_is_empty_array(directives) ){
                new = (apn_node_t**)apr_array_pop(directives);
                if(new) {
                    coming_node = *new;
                    rv = apn_delete_node(coming_node);
                    if (rv != APR_SUCCESS) return rv;
                }
            }

            /** merging */
            if (need_merge){
                if (base_node == NULL) {
                    apn_error("base_node is null.\n");
                    return APR_EGENERAL;
                }
                rv = apn_insert_node( apn_dup_node(base_node), APN_HTTP_MAIN );
                if (rv != APR_SUCCESS) return rv;

                rv = apn_delete_node( base_node);
                if (rv != APR_SUCCESS) return rv;
            }
        }
    }

    return APR_SUCCESS;
}

static int apn_init(apr_pool_t *p, server_rec *s)
{
    if ( !p || !s ){
        // p and s are need to initialized.
        return APR_EINIT;
    }

    /** just set the pool */
    apn_init_conftree(p, 0, 0);

    /** setting the user and group */
    const char *user = unixd_config.user_name;
    const char *group = unixd_config.group_name;
	if(!user) user = DEFAULT_USER;
	if(!group) group = DEFAULT_GROUP;

    char *user_group = apr_pstrcat(p, user, " ", group, NULL);
    apn_node_t *new_node = apn_new_node("user", user_group);
    if (new_node == NULL) {
        apn_error("Failed to new a node.\n");
        return APR_EINIT;
    }

    int rv = apn_insert_node(new_node, APN_MAIN);
    if (rv != APR_SUCCESS){
        apn_error("insert user and group error.\n");
        return APR_EINIT;
    }

    /** to init with the default main direcitves. */
    apn_init_conftree(p, (const char**)default_main_directives, APN_MAIN); 
    
    /** to init with the default events direcitves. */
    apn_init_conftree(p, (const char**)default_events_directives, APN_EVENT); 
    
    /** to init with the default http direcitves. */
    apn_init_conftree(p, (const char**)default_http_directives, APN_HTTP_MAIN); 

    /** insert all virtual host */
    apn_node_t *node;
    if (s->next) {
        s = s->next;
        have_virtual_host = 0;
    }else{
        have_virtual_host = -1;
    }

    while (s){
        have_virtual_host++;
        node = apn_new_node("server","{");
        if (node == NULL) {
            apn_error("Failed to new a node.\n");
            return APR_EGENERAL;
        }
        node->location = APN_HTTP_MAIN;
        node->serverid = have_virtual_host;
        apn_insert_node( node, APN_HTTP_MAIN );

        /** we remember the server in apn_server_list. */
        apn_server_insert(p, node);

        s = s->next;
    }

    return APR_SUCCESS;
}

static const char* ngx_limited_directives[] = {
    "perl",
    "allow", 
    "deny",
    "auth_basic", 
    "auth_basic_user_file",
    "access_log",
    "proxy_pass"
};

static int is_ngx_limited_supported( const char* directive )
{
    if(!directive) return 0;

    int i;
    int sum = sizeof(ngx_limited_directives) / sizeof(const char*);

    for(i = 0; i < sum; i++) {
        if (strcasecmp(directive, ngx_limited_directives[i]) == 0 ){
            return 1;
        }
    }

    return 0;
}

/** brief check the apn_conftree, and find the error.
 *    @return 
 */
static int apn_checking(apr_pool_t *pool)
{
    apn_node_t* p = apn_conftree;
    if ( !p ){
        apn_error("apn_checking: apn_conftree is not built yet.\n");
        return APR_EGENERAL;
    }

    apr_array_header_t *directives 
        = apr_array_make(pool, 1, sizeof(apn_node_t *));

    apn_node_t *current = NULL;
    apn_node_t *next = NULL;
    apn_node_t **new;

    /** calculate the sum */
    while(p){
        if( !strcasecmp(p->directive, "limit_except") ){
            next = p->first_child;
            while (next){
                current = next;
                next = next->next;
                if(!is_ngx_limited_supported(current->directive)){
                    apn_remove_subtree(current);
                }
            }
        }
        if ( p->first_child ) {
            if( p->next ) {
                new = (apn_node_t**)apr_array_push(directives);
                *new = p->next;
            }

            p = p->first_child;
        }else{
            p = p->next;
            if (!p) {
                new = (apn_node_t**)apr_array_pop(directives);
                if (new) p = *new;
            }
        }
    }

    return APR_SUCCESS;
}

#define APN_THICK_LINE_COMP(arg) \
    "\n============================\n  %s\n============================\n", arg
#define APN_THIN_LINE_COMP(arg) \
    "\n----------------------------\n  %s\n----------------------------\n", arg
#define APN_THIN_LINE \
    "----------------------------"
#define APN_OUTPUT_SECIFICATION \
    "\n" \
    "#\n" \
    "# This file was produced by "APN_PROGRAM_INFO",\n" \
    "# a command line tool, which is used to generate Nginx conf\n" \
    "# file according to the Apache conf file.\n" \
    "\n" \
    "# There is no guarantee of that the conf file of Nginx will\n" \
    "# work perfectly.\n" \
    "\n" \
    "# There are two sections in this file. \n" \
    "# The section 1 is the converted directives, \n" \
    "# and the section 2 is the detail list of unconverted directives.\n" \
    "#\n" \
    "\n" 
#define APN_OUTPUT_DIRECTIVES \
    "\n" \
    "#\n" \
    "### Section 1: Nginx directives ###\n" \
    "#\n" \
    "\n" 
#define APN_OUTPUT_UNCONVERTED \
    "\n" \
    "#\n" \
    "### Section 2: Unconverted directives ###\n" \
    "#\n" 

#define APN_OUTPUT_FLAG_DESCRIPTION \
    "\no Flag Description\n" \
    "  [S] Unsupported directives.\n" \
    "  [R] Unrecognized directives.\n" \
    "  [E] Error directives.\n" \
    "  [N] Needless converted directives.\n" \
    "  [K] Unknown directives.\n" 

/* for conf file, we need add '#' before eache line */
static void apn_conf_file_printf(apr_pool_t *p,
        apr_file_t *f, const char* str)
{
    if(!str) return;

    const char* newstr = "";
    char* oldstr = apr_pstrdup(p, str);
    char *retval;
    char *state;
    do {
        retval = apr_strtok(oldstr, "\n", &state);
        if (retval ){
            newstr = apr_pstrcat(p, newstr, "\n# ", retval, NULL);
        }
        oldstr = NULL;
    }while (retval);
    newstr = apr_pstrcat(p, newstr, "\n", NULL);

    apr_file_printf(f, newstr);
}

static int apn_output_statistics(apr_pool_t *pool, apr_file_t *f,
        int* p_sum, int *p_converted_sum)
{
    ap_directive_t* p = ap_conftree;
    if ( !p ){
        apn_error("ap_conftree is not built yet.\n");
        return APR_EGENERAL;
    }

    apr_array_header_t *directives 
        = apr_array_make(pool, 1, sizeof(ap_directive_t*));

    int sum = 0;
    int unsupported_sum = 0;
    int unrecognized_sum = 0;
    int error_sum = 0;
    int needless_process_sum = 0;
    int converted_sum = 0;
    ap_directive_t **new;

    while(p){
        if( p->flag & PARAM_UNSUPPORTED ){
            unsupported_sum++;
        }

        if( p->flag & PARAM_UNRECOGNIZED ){
            unrecognized_sum++;
		}

        if( p->flag & PARAM_ERROR ){
            error_sum++;
		}

        if( p->flag & PARAM_NEEDLESS_PROCESS ){
            needless_process_sum++;
		}

        if( !(p->flag & PARAM_UNCONVERTED) ){
            converted_sum++;
		}

        sum++;
        if ( p->first_child ) {
            if (p->next) {
                new = (ap_directive_t **)apr_array_push(directives);
                *new = p->next;
            }

            p = p->first_child;
        }else{
            p = p->next;
            if (!p) {
                new = (ap_directive_t**)apr_array_pop(directives);
                if (new) p = *new;
            }
        }
    }

    /** pass to param for use later */
    *p_sum = sum;
    *p_converted_sum = converted_sum;

    if( sum == 0 ) {
        apn_error("The sum of directives in the apache config file is 0");
        return APR_EGENERAL;
    }

    const char* str = NULL;
	int unconverted_sum = sum - converted_sum; 

    /** output, statistic convertion rate. */
    float rate = (converted_sum * 100) / sum;
    str = apr_psprintf(pool, 
            "\no Total directives: %d\n" \
            "o Converting Rate: %.2f%%(%d/%d)\n" \
            "o Success: %d\n", 
            sum, rate, converted_sum, sum,
            converted_sum);
    printf(str);
    apn_conf_file_printf(pool, f, str);

    if( unconverted_sum == 0 ) {
        return APR_SUCCESS;
    }

    /** more detailed print */
    str = apr_psprintf(pool, "o Failure: %d\n", unconverted_sum);

    char *tmpStr = NULL;
    if(unsupported_sum > 0 ){
        tmpStr = apr_psprintf(pool, "  - Unsupported: %d\n", 
                unsupported_sum);
        str = apr_pstrcat(pool, str, tmpStr, NULL);
    }

    if(error_sum > 0 ){
        tmpStr = apr_psprintf(pool, "  - Error: %d\n", error_sum);
        str = apr_pstrcat(pool, str, tmpStr, NULL);
    }

    if(unrecognized_sum > 0 ){
        tmpStr = apr_psprintf(pool, "  - Unrecognized: %d\n", 
                unrecognized_sum);
        str = apr_pstrcat(pool, str, tmpStr, NULL);
    }

    if(needless_process_sum > 0 ){
        tmpStr = apr_psprintf(pool, "  - Needless: %d\n", 
                needless_process_sum);
        str = apr_pstrcat(pool, str, tmpStr, NULL);
    }

    int unknown_sum = 
        unconverted_sum - 
        (unsupported_sum + unrecognized_sum + error_sum + needless_process_sum);
    if(unknown_sum > 0) {
        tmpStr = apr_psprintf(pool, "  - Unknown: %d\n", unknown_sum);
        str = apr_pstrcat(pool, str, tmpStr, NULL);
    }

    printf("%s", str);
    apn_conf_file_printf(pool, f, str);

	return APR_SUCCESS;
}

/** brief travel the ap_conftree, 
 *    @param p pool
 *    @return 
 */
static int apn_output_unsupported_list(apr_pool_t *pool, apr_file_t *f)
{
    ap_directive_t* p = ap_conftree;
    if ( !p ){
        apn_error("ap_conftree is not built yet.\n");
        return APR_EGENERAL;
    }
 
	/* Output detail */
    const char* old_conf_file = NULL;
    const char* module_name = NULL;
	const char* str = NULL;
    apr_array_header_t *directives =
        apr_array_make(pool, 1, sizeof(ap_directive_t*));
    ap_directive_t **new;
	int parent_flag = 0;

    /** Flag Description */
    str = APN_OUTPUT_FLAG_DESCRIPTION;
    printf(str);
    apn_conf_file_printf(pool, f, str);

    while(p){
        str = NULL;
		parent_flag = p->parent? 
				p->parent->flag & PARAM_UNCONVERTED
				: 0;
		if( ( p->flag & PARAM_UNCONVERTED)
			|| parent_flag ){
            if (p->directive && p->args) {
                str = "";
                if (!old_conf_file || strcmp(old_conf_file, p->filename) != 0) {
                    str = apr_psprintf(pool,
                            "\nIn conf file: %s\n%s\n", 
                            p->filename, APN_THIN_LINE);
                    old_conf_file = p->filename;
                }
                module_name = apn_get_module_name(pool, p->directive);
                str = apr_pstrcat(pool, str,
                        apr_psprintf(pool, "Line %d: %s %s (%s)\n", 
                        p->line_num, p->directive, p->args, 
                        module_name? module_name: "unknown module"),
                        NULL
                        );
				if(p->flag & PARAM_UNSUPPORTED)
					str = apr_pstrcat(pool, str, "[S]", NULL);
				if(p->flag & PARAM_UNRECOGNIZED) 
					str = apr_pstrcat(pool, str, "[R]", NULL);
				if(p->flag & PARAM_ERROR) 
					str = apr_pstrcat(pool, str, "[E]", NULL);
				if(p->flag & PARAM_NEEDLESS_PROCESS) 
					str = apr_pstrcat(pool, str, "[N]", NULL);
				if(!(p->flag & PARAM_UNDEFINE) && 
                        !(p->flag & PARAM_UNCONVERTED)){
					str = apr_pstrcat(pool, str, "[K]", NULL);
                }

                if(p->errmsg){
                str = apr_pstrcat(pool, str,
                        apr_psprintf(pool, "  %s\n\n", p->errmsg), 
                        NULL);
				} else if ( parent_flag ){
                str = apr_pstrcat(pool, str,
                        apr_psprintf(pool, "  %s\n\n", MSG_INHERIT_PARENT),
                        NULL);
                }
            }
        }
        if(str){
            printf(str);
            apn_conf_file_printf(pool, f, str);
        }

        if ( p->first_child ) {
            if( p->next ) {
                *(ap_directive_t**)apr_array_push(directives) = p->next;
            }
            p = p->first_child;
        }else{
            p = p->next;
            if (!p) {
                new = (ap_directive_t**)apr_array_pop(directives);
                if (new ) p = *new;
            }
        }
    }

	printf("\n");

    return APR_SUCCESS;
}

/** brief write to the nginx.conf
 *    @param p
 *    @param filename
 *    @return 
 */
static apr_status_t apn_write_nginx_conf_file( apr_pool_t *p, 
        const char* filename )
{
    apr_file_t *f;
    apr_status_t rv;

    /* Remove the empty nginx.conf. */
    apr_file_remove(filename, p);

    rv = apr_file_open(&f, filename,
                APR_CREATE|APR_APPEND|APR_WRITE,
                APR_OS_DEFAULT, p);
    if (rv != APR_SUCCESS ){
        apn_error("open file error.\n");
        return rv;
    }

    /* Specification Head */
    apr_file_printf(f, APN_OUTPUT_SECIFICATION);

    /** calculate the sum */
    int sum, converted_sum;
    printf( APN_THICK_LINE_COMP("Converting Summary") );
	apn_output_statistics(p, f, &sum, &converted_sum);
    if (rv != APR_SUCCESS){
        return rv;
    }

    /* Config file Content */
    apr_file_printf(f, APN_OUTPUT_DIRECTIVES);
    rv = apn_output_conftree(f);
    if (rv != APR_SUCCESS){
        return rv;
    }

    /** tell user which directives we not supported or identified*/
    if( sum > converted_sum ){
        apr_file_printf(f, APN_OUTPUT_UNCONVERTED);
        printf( APN_THICK_LINE_COMP("Unconverted Detail") );
        rv = apn_output_unsupported_list(p, f);
        if (rv != APR_SUCCESS) {
            ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, p,
                    "%s", "apn output not supported directives list error!");
            return APR_EGENERAL;
        }
    }

    apr_file_close(f);
    return APR_SUCCESS;
}

/**
 * Migrate config to nginx format, and output by ngx config file.
 * @param p The pool for general allocation
 * @param s The server rec to use in the command parms
 * @param ngx_confname The config file of nginx for output.
 * @return OK if no problems
 */
AP_DECLARE(int) apn_migrate_to_nginx( apr_pool_t *p,
                                      server_rec *s,
                                      const char* ngx_confname )
{
    apr_status_t rv;
    
    /** init the apn conftree, add the http
     *  add the events {, http {, default server.
     *  init directive table, db.
     */
    rv = apn_init( p, s );
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, p,
                     "%s", "apn init error!");
        return APR_EGENERAL;
    }
    
    /** migrate to nginx directive, generated apn_conftree */
    rv = apn_migration(p, s, ngx_confname);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, p,
                     "%s", "apn migration error!");
        return APR_EGENERAL;
    }

    /**
     *  When the same directive configurated in each server,
     *  we should merge it to http field.
     *  There are some directives can't configurated
     *  each server, for example, logformat.
     *  and in this case, we have to do merge.
     */
    rv = apn_merging(p);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, p,
                "%s", "apn merging error!");
        return APR_EGENERAL;
    }

    /** check */
    rv = apn_checking(p);
    if (rv != APR_SUCCESS) {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, p,
                     "%s", "apn checking error!");
        return APR_EGENERAL;
    }
    
    /** write to the nginx.conf */
    rv = apn_write_nginx_conf_file( p, ngx_confname );
    if (rv == APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                "Completed! The generated nginx conf file is %s.", ngx_confname);
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, 
                " ");
    } else {
        ap_log_perror(APLOG_MARK, APLOG_STARTUP, 0, p,
                     "%s", "write conf file error! "
                     "You should set a correct output file with -o option.");
        return APR_EGENERAL;
    }

    return APR_SUCCESS;
}

