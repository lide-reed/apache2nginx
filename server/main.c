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
 * Based on the code of Apache Httpd, Written by: 
 *   Reed Lee <mailtolide@sina.com>
 */

#include "apr.h"
#include "apr_strings.h"
#include "apr_getopt.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "apr_md5.h"
#include "apr_time.h"
#include "apr_version.h"
#include "apu_version.h"

#define APR_WANT_STDIO
#define APR_WANT_STRFUNC
#include "apr_want.h"

#define CORE_PRIVATE
#include "ap_config.h"
#include "httpd.h"
#include "http_main.h"
#include "http_log.h"
#include "http_config.h"
#include "http_core.h"
#include "http_vhost.h"
#include "apr_uri.h"
#include "util_ebcdic.h"
#include "ap_mpm.h"
#include "mpm_common.h"

#define APN_SERVER_BASEARGS "f:o:d:vhlL?" /*"C:c:D:d:E:e:f:vVlLtTSMh?X"*/

/* WARNING: Win32 binds http_main.c dynamically to the server. Please place
 *          extern functions and global data in another appropriate module.
 *
 * Most significant main() global data can be found in http_config.c
 */

#define TASK_SWITCH_SLEEP 10000

static void destroy_and_exit_process(process_rec *process,
                                     int process_exit_value)
{
    /*
     * Sleep for TASK_SWITCH_SLEEP micro seconds to cause a task switch on
     * OS layer and thus give possibly started piped loggers a chance to
     * process their input. Otherwise it is possible that they get killed
     * by us before they can do so. In this case maybe valueable log messages
     * might get lost.
     */
    apr_sleep(TASK_SWITCH_SLEEP);
    apr_pool_destroy(process->pool); /* and destroy all descendent pools */
    apr_terminate();
    exit(process_exit_value);
}

static process_rec *init_process(int *argc, const char * const * *argv)
{
    process_rec *process;
    apr_pool_t *cntx;
    apr_status_t stat;
    const char *failed = "apr_app_initialize()";

    stat = apr_app_initialize(argc, argv, NULL);
    if (stat == APR_SUCCESS) {
        failed = "apr_pool_create()";
        stat = apr_pool_create(&cntx, NULL);
    }

    if (stat != APR_SUCCESS) {
        /* For all intents and purposes, this is impossibly unlikely,
         * but APR doesn't exist yet, we can't use it for reporting
         * these earliest two failures;
         */
        char ctimebuff[APR_CTIME_LEN];
        apr_ctime(ctimebuff, apr_time_now());
        fprintf(stderr, "[%s] [crit] (%d) %s: %s failed "
                        "to initial context, exiting\n", 
                        ctimebuff, stat, (*argv)[0], failed);
        apr_terminate();
        exit(1);
    }

    apr_pool_tag(cntx, "process");
    ap_open_stderr_log(cntx);

    /* Now we have initialized apr and our logger, no more
     * exceptional error reporting required for the lifetime
     * of this server process.
     */

    process = apr_palloc(cntx, sizeof(process_rec));
    process->pool = cntx;

    apr_pool_create(&process->pconf, process->pool);
    apr_pool_tag(process->pconf, "pconf");
    process->argc = *argc;
    process->argv = *argv;
    process->short_name = apr_filepath_name_get((*argv)[0]);
    return process;
}

static void usage(process_rec *process)
{
    const char *bin = process->argv[0];
    int pad_len = strlen(bin);

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "Version: "APN_PROGRAM_INFO);

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 " ");

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "Usage: %s [-f file] [-d directory] [-o file]", bin);

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "       %*s [-l] [-L] [-?] [-h]",
                 pad_len, " ");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "Options:");

    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -f file            : set apache configuration file ");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -o file            : set nginx configuration file "
                 "(default: ./nginx.conf)");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -d directory       : specify an alternate initial "
                 "ServerRoot");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -h                 : list available command line options "
                 "(this page)");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -l                 : list supported modules");
    ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL,
                 "  -L                 : list supported directives and its description "
                 "directives");

}

/**
 * if ap_server_root is /xxx/xxx/conf, 
 * and the /xxx/xxx/conf.d exist,
 * we set it to /xxx/xxx
 */
static void apn_fixed_server_root( apr_pool_t *p)
{
	if (!ap_server_root) return;
	char* path = apr_pstrdup(p, ap_server_root);
	int len = strlen(path);
	const char* conf = "conf";
	if ((len > strlen(conf)) && 
			!strcmp(path + len-strlen(conf), conf)){
		char *dir = apr_pstrcat(p, ap_server_root, ".d", NULL);
		if (ap_is_directory(p, dir)) {
			path[len-strlen(conf)] = '\0';
			ap_server_root = path;
		}
	}
}

int main(int argc, const char * const argv[])
{
    char c;
    const char *ap_confname = "httpd.conf";
    const char *ngx_confname = "nginx.conf";
    const char *def_server_root = NULL;
    const char *temp_error_log = NULL;
    const char *error;
    process_rec *process;
    server_rec *server_conf;
    apr_pool_t *pglobal;
    apr_pool_t *pconf;
    apr_pool_t *plog; /* Pool of log streams, reset _after_ each read of conf */
    apr_pool_t *ptemp; /* Pool for temporary config stuff, reset often */
    apr_pool_t *pcommands; /* Pool for -D, -C and -c switches */
    apr_getopt_t *opt;
    apr_status_t rv;
    const char *optarg;

    AP_MONCONTROL(0); /* turn off profiling of startup */

    process = init_process(&argc, &argv);
    pglobal = process->pool;
    pconf = process->pconf;
    ap_server_argv0 = process->short_name;

#if APR_CHARSET_EBCDIC
    if (ap_init_ebcdic(pglobal) != APR_SUCCESS) {
        destroy_and_exit_process(process, 1);
    }
#endif

    apr_pool_create(&pcommands, pglobal);
    apr_pool_tag(pcommands, "pcommands");
    ap_server_pre_read_config  = apr_array_make(pcommands, 1, sizeof(char *));
    ap_server_post_read_config = apr_array_make(pcommands, 1, sizeof(char *));
    ap_server_config_defines   = apr_array_make(pcommands, 1, sizeof(char *));

    error = ap_setup_prelinked_modules(process);
    if (error) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP|APLOG_EMERG, 0, NULL, "%s: %s",
                     ap_server_argv0, error);
        destroy_and_exit_process(process, 1);
    }

    ap_run_rewrite_args(process);

    /* Maintain AP_SERVER_BASEARGS list in http_main.h to allow the MPM
     * to safely pass on our args from its rewrite_args() handler.
     */
    apr_getopt_init(&opt, pcommands, process->argc, process->argv);

    while ((rv = apr_getopt(opt, APN_SERVER_BASEARGS, &c, &optarg))
            == APR_SUCCESS) {
        switch (c) {

        case 'f':
            ap_confname = optarg;
            break;

        case 'o':
            ngx_confname = optarg;
            break;

        case 'd':
            def_server_root = optarg;
            break;

        case 'l':
            ap_show_modules();
            destroy_and_exit_process(process, 0);

        case 'L':
            ap_show_directives();
            destroy_and_exit_process(process, 0);

        case 'h':
        case '?':
            usage(process);
            destroy_and_exit_process(process, 0);
        }
    }

    if (rv != APR_EOF || argc < 3) {
        if (c != 'h' && c != '?') {
            usage(process);
        }
        destroy_and_exit_process(process, 1);
    }

    apr_pool_create(&plog, pglobal);
    apr_pool_tag(plog, "plog");
    apr_pool_create(&ptemp, pconf);
    apr_pool_tag(ptemp, "ptemp");

	/** we need the real path */
	char* fullpath = NULL;
	rv = apr_get_realpath(&fullpath, ap_confname, plog);
	if (rv != APR_SUCCESS){
		apn_error("Apache conf file is not found " 
				"or the given path is invalid! Exit.\n");
		destroy_and_exit_process(process, 1);
	}
	ap_confname = apr_pstrdup(plog, fullpath);

    /* Note that we preflight the config file once
     * before reading it _again_ in the main loop.
     * This allows things, log files configuration
     * for example, to settle down.
     */
    ap_server_root = def_server_root;
    if (!ap_server_root){ // no specify serverroot by -d in commandline.

        if (!ap_confname) {
            apn_error("Apache conf file name is null!\n");
            destroy_and_exit_process(process, 1);
        }

        /**
         * if ap_confname is absolute path, get the prefix as serverroot.
         * if it is not, set the current path as serverroot.
         */
        char* basedir;
        rv = apr_get_basedir(&basedir, ap_confname, process->pool);
        if(rv!=APR_SUCCESS){
            apn_error("Apache conf file is not found " 
                    "or the given path is invalid! Exit.\n");
            destroy_and_exit_process(process, 1);
        }

        ap_server_root = def_server_root = basedir;

		/**
		 * Sometimes, ap_server_root should be set more intelligence.
		 * Because of apache conf depend on the ServerRoot.
		 * when not in localhost, maybe ServerRoot is not valid,
		 * and here need to guess the ap_server_root.
		 */
		apn_fixed_server_root(plog);
    }
    if (temp_error_log) {
        ap_replace_stderr_log(process->pool, temp_error_log);
    }

    char *ngx_fullpath = NULL;
    rv = apr_get_realpath(&ngx_fullpath, ngx_confname, plog);
    if (rv == APR_SUCCESS) {
        apn_error("Config file exists: %s. Exit.\n", ngx_fullpath);
        destroy_and_exit_process(process, 1);
    } else {
        /* Create a empty nginx.conf, because mod_mime needs this file. */
        apr_file_t *f;
        rv = apr_file_open(&f, ngx_confname, 
                APR_CREATE|APR_APPEND|APR_WRITE,
                APR_OS_DEFAULT, plog);
        if (rv != APR_SUCCESS) {
            apn_error("Create file error: %s\n", ngx_fullpath);
            destroy_and_exit_process(process, 1);
        }
        apr_file_close(f);
    }

    /*
     * here just create the main server, and the vhost is not created.
     */
    server_conf = ap_read_config(process, ptemp, ap_confname, &ap_conftree);
    if (!server_conf) {
        destroy_and_exit_process(process, 1);
    }
    /* sort hooks here to make sure pre_config hooks are sorted properly */
    apr_hook_sort_all();

    if (ap_run_pre_config(pconf, plog, ptemp) != OK) {
        ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR, 0,
                     NULL, "Pre-configuration failed");
        destroy_and_exit_process(process, 1);
    }

    /* Lijinhu added : check the configuration validation */
    if (ap_conftree == NULL) {
        apn_error("The apache conf file is invalid! Please check it. Exit.\n");
        destroy_and_exit_process(process, 1);
    }

    rv = ap_process_config_tree(server_conf, ap_conftree,
                                process->pconf, ptemp);
    if (rv == OK) {
        /*
         * 1. merge server configs.
         * 2. merge per dir configs for each server.
         * 3. re-order the directorise.
         */
        ap_fixup_virtual_hosts(pconf, server_conf);

        /* compile the tables and such we need to do the run-time vhost lookups */
        ap_fini_vhost_config(pconf, server_conf);

        /*
         * Sort hooks again because ap_process_config_tree may have added
         * modules and hence hooks. This happens with mod_perl and modules
         * written in perl.
         */
        apr_hook_sort_all();

        ap_run_test_config(pconf, server_conf);
        ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, "Syntax OK");

        if ( ap_run_post_config(pconf, plog, ptemp, server_conf) != OK) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP |APLOG_ERR, 0,
                    NULL, "Failed when merge some configurations");
            destroy_and_exit_process(process, 1);
        }


        /*
         * migrate the config to nginx conf format.
         * generate the conf file of nginx.
         */
        rv = apn_migrate_to_nginx(plog, server_conf, ngx_confname);
        if (rv != OK) {
            ap_log_error(APLOG_MARK, APLOG_STARTUP, 0, NULL, "Migrate Error!");
        }
        destroy_and_exit_process(process, 0);
    }

   return 0; /* Termination 'ok' */
}

#ifdef AP_USING_AUTOCONF
/* This ugly little hack pulls any function referenced in exports.c into
 * the web server.  exports.c is generated during the build, and it
 * has all of the APR functions specified by the apr/apr.exports and
 * apr-util/aprutil.exports files.
 */
const void *suck_in_APR(void);
const void *suck_in_APR(void)
{
    extern const void *ap_ugly_hack;

    return ap_ugly_hack;
}
#endif
