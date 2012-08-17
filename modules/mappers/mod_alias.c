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
 * http_alias.c: Stuff for dealing with directory aliases
 *
 * Original by Rob McCool, rewritten in succession by David Robinson
 * and rst.
 *
 */

/*
 * Based on the code of Apache Httpd, Written by: 
 *   James Lee <jsandjh@gmail.com>
 */

#include "apr_strings.h"
#include "apr_lib.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"


typedef struct {
    const char *real;
    const char *fake;
    char *handler;
    ap_regex_t *regexp;
    int redir_status;                /* 301, 302, 303, 410, etc */
} alias_entry;

typedef struct {
    apr_array_header_t *aliases;
    apr_array_header_t *redirects;

    //server_rec         *server;
} alias_server_conf;

typedef struct {
    apr_array_header_t *redirects;
} alias_dir_conf;

module AP_MODULE_DECLARE_DATA alias_module;

/* Li Jinhu  */
typedef struct {
    alias_server_conf *gconf;
    server_rec *server;
} alias_rec;
static apr_array_header_t *alias_recs = NULL;

static void *create_alias_config(apr_pool_t *p, server_rec *s)
{
    alias_server_conf *a =
    (alias_server_conf *) apr_pcalloc(p, sizeof(alias_server_conf));

    a->aliases = apr_array_make(p, 20, sizeof(alias_entry));
    a->redirects = apr_array_make(p, 20, sizeof(alias_entry));
    return a;
}

static void *create_alias_dir_config(apr_pool_t *p, char *d)
{
    alias_dir_conf *a =
    (alias_dir_conf *) apr_pcalloc(p, sizeof(alias_dir_conf));
    a->redirects = apr_array_make(p, 2, sizeof(alias_entry));
    return a;
}

static void *merge_alias_config(apr_pool_t *p, void *basev, void *overridesv)
{
    alias_server_conf *a =
    (alias_server_conf *) apr_pcalloc(p, sizeof(alias_server_conf));
    alias_server_conf *base = (alias_server_conf *) basev;
    alias_server_conf *overrides = (alias_server_conf *) overridesv;

    a->aliases = apr_array_append(p, overrides->aliases, base->aliases);
    a->redirects = apr_array_append(p, overrides->redirects, base->redirects);
    return a;
}

static void *merge_alias_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    alias_dir_conf *a =
    (alias_dir_conf *) apr_pcalloc(p, sizeof(alias_dir_conf));
    alias_dir_conf *base = (alias_dir_conf *) basev;
    alias_dir_conf *overrides = (alias_dir_conf *) overridesv;
    a->redirects = apr_array_append(p, overrides->redirects, base->redirects);
    return a;
}

/* need prototype for overlap check */
static int alias_matches(const char *uri, const char *alias_fakename);

static const char *add_alias_internal(cmd_parms *cmd, void *dummy,
                                      const char *f, const char *r,
                                      int use_regex)
{
    server_rec *s = cmd->server;
    alias_server_conf *conf = ap_get_module_config(s->module_config,
                                                   &alias_module);
    alias_entry *new = apr_array_push(conf->aliases);
    alias_entry *entries = (alias_entry *)conf->aliases->elts;
    int i;

    /* XX r can NOT be relative to DocumentRoot here... compat bug. */

    if (use_regex) {
        new->regexp = ap_pregcomp(cmd->pool, f, AP_REG_EXTENDED);
        if (new->regexp == NULL)
            return "Regular expression could not be compiled.";
        new->real = r;
    }
    else {
        /* XXX This may be optimized, but we must know that new->real
         * exists.  If so, we can dir merge later, trusing new->real
         * and just canonicalizing the remainder.  Not till I finish
         * cleaning out the old ap_canonical stuff first.
         */
        new->real = r;
    }
    new->fake = f;
    new->handler = cmd->info;

    /* Li Jinhu added. */
    if (alias_recs == NULL) {
        alias_recs = apr_array_make(cmd->pool, 10, sizeof(alias_rec));
    }
    /* if not exist, add to array. */
    int j;
    int found = 0;
    for (j = 0; j < alias_recs->nelts; ++j) {
        alias_rec *item = (alias_rec *)alias_recs->elts;
        if (item[j].server == cmd->server) {
            found = 1;
            break;
        }
    }
    if (!found) {
        alias_rec *new_alias_rec = apr_array_push(alias_recs);
        new_alias_rec->server = cmd->server;
        new_alias_rec->gconf = conf;
    }


    /* check for overlapping (Script)Alias directives
     * and throw a warning if found one
     */
    if (!use_regex) {
        for (i = 0; i < conf->aliases->nelts - 1; ++i) {
            alias_entry *p = &entries[i];

            if (  (!p->regexp &&  alias_matches(f, p->fake) > 0)
                || (p->regexp && !ap_regexec(p->regexp, f, 0, NULL, 0))) {
                ap_log_error(APLOG_MARK, APLOG_WARNING, 0, cmd->server,
                             "The %s directive in %s at line %d will probably "
                             "never match because it overlaps an earlier "
                             "%sAlias%s.",
                             cmd->cmd->name, cmd->directive->filename,
                             cmd->directive->line_num,
                             p->handler ? "Script" : "",
                             p->regexp ? "Match" : "");

                break; /* one warning per alias should be sufficient */
            }
        }
    }

    return NULL;
}

static const char *add_alias(cmd_parms *cmd, void *dummy, const char *f,
                             const char *r)
{
    return add_alias_internal(cmd, dummy, f, r, 0);
}

static const char *add_alias_regex(cmd_parms *cmd, void *dummy, const char *f,
                                   const char *r)
{
    return add_alias_internal(cmd, dummy, f, r, 1);
}

static const char *add_redirect_internal(cmd_parms *cmd,
                                         alias_dir_conf *dirconf,
                                         const char *arg1, const char *arg2,
                                         const char *arg3, int use_regex)
{
    alias_entry *new;
    server_rec *s = cmd->server;
    alias_server_conf *serverconf = ap_get_module_config(s->module_config,
                                                         &alias_module);
    int status = (int) (long) cmd->info;
    int grokarg1 = 1;
    ap_regex_t *r = NULL;
    const char *f = arg2;
    const char *url = arg3;

    /*
     * Logic flow:
     *   Go ahead and try to grok the 1st arg, in case it is a
     *   Redirect status. Now if we have 3 args, we expect that
     *   we were able to understand that 1st argument (it's something
     *   we expected, so if not, then we bail
     */
    if (!strcasecmp(arg1, "permanent"))
        status = HTTP_MOVED_PERMANENTLY;
    else if (!strcasecmp(arg1, "temp"))
        status = HTTP_MOVED_TEMPORARILY;
    else if (!strcasecmp(arg1, "seeother"))
        status = HTTP_SEE_OTHER;
    else if (!strcasecmp(arg1, "gone"))
        status = HTTP_GONE;
    else if (apr_isdigit(*arg1))
        status = atoi(arg1);
    else
        grokarg1 = 0;

    if (arg3 && !grokarg1)
        return "Redirect: invalid first argument (of three)";

    /*
     * if we don't have the 3rd arg and we didn't understand the 1st
     * one, then assume URL-path URL. This also handles case, eg, GONE
     * we even though we don't have a 3rd arg, we did understand the 1st
     * one, so we don't want to re-arrange
     */
    if (!arg3 && !grokarg1) {
        f = arg1;
        url = arg2;
    }

    if (use_regex) {
        r = ap_pregcomp(cmd->pool, f, AP_REG_EXTENDED);
        if (r == NULL)
            return "Regular expression could not be compiled.";
    }

    if (ap_is_HTTP_REDIRECT(status)) {
        if (!url)
            return "URL to redirect to is missing";
        /* PR#35314: we can allow path components here;
         * they get correctly resolved to full URLs.
         */
        if (!use_regex && !ap_is_url(url) && (url[0] != '/'))
            return "Redirect to non-URL";
    }
    else {
        if (url)
            return "Redirect URL not valid for this status";
    }

    if (cmd->path)
        new = apr_array_push(dirconf->redirects);
    else
        new = apr_array_push(serverconf->redirects);

    new->fake = f;
    new->real = url;
    new->regexp = r;
    new->redir_status = status;
    return NULL;
}

static const char *add_redirect(cmd_parms *cmd, void *dirconf,
                                const char *arg1, const char *arg2,
                                const char *arg3)
{
    return add_redirect_internal(cmd, dirconf, arg1, arg2, arg3, 0);
}

static const char *add_redirect2(cmd_parms *cmd, void *dirconf,
                                 const char *arg1, const char *arg2)
{
    return add_redirect_internal(cmd, dirconf, arg1, arg2, NULL, 0);
}

static const char *add_redirect_regex(cmd_parms *cmd, void *dirconf,
                                      const char *arg1, const char *arg2,
                                      const char *arg3)
{
    return add_redirect_internal(cmd, dirconf, arg1, arg2, arg3, 1);
}

static const command_rec alias_cmds[] =
{
    AP_INIT_TAKE2("Alias", add_alias, NULL, RSRC_CONF,
                  "a fakename and a realname"),
    AP_INIT_TAKE2("ScriptAlias", add_alias, "cgi-script", RSRC_CONF,
                  "a fakename and a realname"),
    AP_INIT_TAKE23("Redirect", add_redirect, (void *) HTTP_MOVED_TEMPORARILY,
                   OR_FILEINFO,
                   "an optional status, then document to be redirected and "
                   "destination URL"),
    AP_INIT_TAKE2("AliasMatch", add_alias_regex, NULL, RSRC_CONF,
                  "a regular expression and a filename"),
    AP_INIT_TAKE2("ScriptAliasMatch", add_alias_regex, "cgi-script", RSRC_CONF,
                  "a regular expression and a filename"),
    AP_INIT_TAKE23("RedirectMatch", add_redirect_regex,
                   (void *) HTTP_MOVED_TEMPORARILY, OR_FILEINFO,
                   "an optional status, then a regular expression and "
                   "destination URL"),
    AP_INIT_TAKE2("RedirectTemp", add_redirect2,
                  (void *) HTTP_MOVED_TEMPORARILY, OR_FILEINFO,
                  "a document to be redirected, then the destination URL"),
    AP_INIT_TAKE2("RedirectPermanent", add_redirect2,
                  (void *) HTTP_MOVED_PERMANENTLY, OR_FILEINFO,
                  "a document to be redirected, then the destination URL"),
    {NULL}
};

static int alias_matches(const char *uri, const char *alias_fakename)
{
    const char *aliasp = alias_fakename, *urip = uri;

    while (*aliasp) {
        if (*aliasp == '/') {
            /* any number of '/' in the alias matches any number in
             * the supplied URI, but there must be at least one...
             */
            if (*urip != '/')
                return 0;

            do {
                ++aliasp;
            } while (*aliasp == '/');
            do {
                ++urip;
            } while (*urip == '/');
        }
        else {
            /* Other characters are compared literally */
            if (*urip++ != *aliasp++)
                return 0;
        }
    }

    /* Check last alias path component matched all the way */

    if (aliasp[-1] != '/' && *urip != '\0' && *urip != '/')
        return 0;

    /* Return number of characters from URI which matched (may be
     * greater than length of alias, since we may have matched
     * doubled slashes)
     */

    return urip - uri;
}

static char *try_alias_list(request_rec *r, apr_array_header_t *aliases,
                            int doesc, int *status)
{
    alias_entry *entries = (alias_entry *) aliases->elts;
    ap_regmatch_t regm[AP_MAX_REG_MATCH];
    char *found = NULL;
    int i;

    for (i = 0; i < aliases->nelts; ++i) {
        alias_entry *p = &entries[i];
        int l;

        if (p->regexp) {
            if (!ap_regexec(p->regexp, r->uri, AP_MAX_REG_MATCH, regm, 0)) {
                if (p->real) {
                    found = ap_pregsub(r->pool, p->real, r->uri,
                                       AP_MAX_REG_MATCH, regm);
                    if (found && doesc) {
                        apr_uri_t uri;
                        apr_uri_parse(r->pool, found, &uri);
                        /* Do not escape the query string or fragment. */
                        found = apr_uri_unparse(r->pool, &uri,
                                                APR_URI_UNP_OMITQUERY);
                        found = ap_escape_uri(r->pool, found);
                        if (uri.query) {
                            found = apr_pstrcat(r->pool, found, "?",
                                                uri.query, NULL);
                        }
                        if (uri.fragment) {
                            found = apr_pstrcat(r->pool, found, "#",
                                                uri.fragment, NULL);
                        }
                    }
                }
                else {
                    /* need something non-null */
                    found = apr_pstrdup(r->pool, "");
                }
            }
        }
        else {
            l = alias_matches(r->uri, p->fake);

            if (l > 0) {
                if (doesc) {
                    char *escurl;
                    escurl = ap_os_escape_path(r->pool, r->uri + l, 1);

                    found = apr_pstrcat(r->pool, p->real, escurl, NULL);
                }
                else
                    found = apr_pstrcat(r->pool, p->real, r->uri + l, NULL);
            }
        }

        if (found) {
            if (p->handler) {    /* Set handler, and leave a note for mod_cgi */
                r->handler = p->handler;
                apr_table_setn(r->notes, "alias-forced-type", r->handler);
            }
            /* XXX This is as SLOW as can be, next step, we optimize
             * and merge to whatever part of the found path was already
             * canonicalized.  After I finish eliminating os canonical.
             * Better fail test for ap_server_root_relative needed here.
             */
            if (!doesc) {
                found = ap_server_root_relative(r->pool, found);
            }
            if (found) {
                *status = p->redir_status;
            }
            return found;
        }

    }

    return NULL;
}

static int translate_alias_redir(request_rec *r)
{
    ap_conf_vector_t *sconf = r->server->module_config;
    alias_server_conf *serverconf = ap_get_module_config(sconf, &alias_module);
    char *ret;
    int status;

    if (r->uri[0] != '/' && r->uri[0] != '\0') {
        return DECLINED;
    }

    if ((ret = try_alias_list(r, serverconf->redirects, 1, &status)) != NULL) {
        if (ap_is_HTTP_REDIRECT(status)) {
            char *orig_target = ret;
            if (ret[0] == '/') {

                ret = ap_construct_url(r->pool, ret, r);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "incomplete redirection target of '%s' for "
                              "URI '%s' modified to '%s'",
                              orig_target, r->uri, ret);
            }
            if (!ap_is_url(ret)) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "cannot redirect '%s' to '%s'; "
                              "target is not a valid absoluteURI or abs_path",
                              r->uri, ret);
                /* restore the config value, so as not to get a
                 * "regression" on existing "working" configs.
                 */
                ret = orig_target;
            }
            /* append requested query only, if the config didn't
             * supply its own.
             */
            if (r->args && !ap_strchr(ret, '?')) {
                ret = apr_pstrcat(r->pool, ret, "?", r->args, NULL);
            }
            apr_table_setn(r->headers_out, "Location", ret);
        }
        return status;
    }

    if ((ret = try_alias_list(r, serverconf->aliases, 0, &status)) != NULL) {
        r->filename = ret;
        return OK;
    }

    return DECLINED;
}

static int fixup_redir(request_rec *r)
{
    void *dconf = r->per_dir_config;
    alias_dir_conf *dirconf =
    (alias_dir_conf *) ap_get_module_config(dconf, &alias_module);
    char *ret;
    int status;

    /* It may have changed since last time, so try again */

    if ((ret = try_alias_list(r, dirconf->redirects, 1, &status)) != NULL) {
        if (ap_is_HTTP_REDIRECT(status)) {
            if (ret[0] == '/') {
                char *orig_target = ret;

                ret = ap_construct_url(r->pool, ret, r);
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                              "incomplete redirection target of '%s' for "
                              "URI '%s' modified to '%s'",
                              orig_target, r->uri, ret);
            }
            if (!ap_is_url(ret)) {
                status = HTTP_INTERNAL_SERVER_ERROR;
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "cannot redirect '%s' to '%s'; "
                              "target is not a valid absoluteURI or abs_path",
                              r->uri, ret);
            }
            else {
                /* append requested query only, if the config didn't
                 * supply its own.
                 */
                if (r->args && !ap_strchr(ret, '?')) {
                    ret = apr_pstrcat(r->pool, ret, "?", r->args, NULL);
                }
                apr_table_setn(r->headers_out, "Location", ret);
            }
        }
        return status;
    }

    return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    static const char * const aszSucc[]={ "mod_userdir.c",
                                          "mod_vhost_alias.c",NULL };

    ap_hook_translate_name(translate_alias_redir,NULL,aszSucc,APR_HOOK_MIDDLE);
    ap_hook_fixups(fixup_redir,NULL,NULL,APR_HOOK_MIDDLE);
}


static char *
rewrite_args(apr_pool_t *pool, alias_entry *entries)
{
    char *arg = NULL;
    char *flags_in_ngx = NULL;
    if (entries->redir_status == HTTP_MOVED_PERMANENTLY) {
        flags_in_ngx = "permanent";
        arg = apr_pstrcat(pool, "\"", entries->fake, "\"", " ", entries->real, " ", flags_in_ngx, NULL);
    } else if (entries->redir_status == HTTP_MOVED_TEMPORARILY) {
        flags_in_ngx = "redirect";
        arg = apr_pstrcat(pool, "\"", entries->fake, "\"", " ", entries->real, " ", flags_in_ngx, NULL);
    } else {
        flags_in_ngx = "redirect";
        arg = apr_pstrcat(pool, "\"", entries->fake, "\"", " ", entries->real, " ", flags_in_ngx, NULL);
    }

    return arg;
}


static apn_module_t* 
convert_alias_in_dir( apr_pool_t *pool, cmd_parms *parms, ap_conf_vector_t* v ) 
{
    apn_module_t *mod = NULL;

    alias_dir_conf *conf = ap_get_module_config(v, &alias_module);
    alias_entry *entries;

    /* initialize real_fake_rec. */
    int i;
    if (parms->real_fake_rec == NULL && alias_recs != NULL) {
        parms->real_fake_rec = apr_table_make(pool, 10);

        for (i = 0; i < alias_recs->nelts; ++i) {
            alias_rec *item = (alias_rec *)alias_recs->elts;
            alias_entry *entries = item[i].gconf->aliases->elts;
            int k;
            for (k = 0; k < item[i].gconf->aliases->nelts; ++k) {
                if (item[i].server == parms->server) {
                    if (entries[k].regexp != NULL) {
                        char *my_fake = apr_pstrcat(pool, "~ ", entries[k].fake, NULL);
                        apr_table_set(parms->real_fake_rec, entries[k].real, my_fake);
                    } else {
                        apr_table_set(parms->real_fake_rec, entries[k].real, entries[k].fake);
                    }
                }
            }
        }
    }

    int j;
    for (j = 0; alias_recs != NULL && j < alias_recs->nelts; ++j) {
        alias_rec *item = (alias_rec *)alias_recs->elts;
        if ( (! item[j].server->is_virtual) || 
             (( item[j].server->is_virtual) && item[j].server == parms->server )) {
            alias_entry *entries = item[j].gconf->aliases->elts;
            int k;
            for (k = 0; k < item[j].gconf->aliases->nelts; ++k) {
                if (parms->path && strcmp(parms->path, entries[k].real) == 0) {
                    mod = apn_mod_insert_sibling(mod, "alias", entries[k].real);
                    parms->alias_path = apr_pstrdup(pool, entries[k].fake);

                    apr_table_unset(parms->real_fake_rec, entries[k].real);
                }
            }
        }
    }

    /* convert : Redirect */
    int n;
    if (conf != NULL) {
        alias_entry *ent = conf->redirects->elts;
        for (n = 0; n < conf->redirects->nelts; n++) {
            char *arg = rewrite_args(pool, ent);
            mod = apn_mod_insert_sibling(mod, "rewrite", arg);

            ent++;
        }
    }

    return mod;
}

static apn_module_t* 
convert_alias_in_server( apr_pool_t *pool, cmd_parms *parms, ap_conf_vector_t* v ) 
{
    apn_module_t *mod = NULL;

    alias_server_conf *conf = ap_get_module_config(v, &alias_module);

    if (conf == NULL) {
        return mod;
    }

    int n;
    alias_entry *entries = conf->redirects->elts;
    for (n = 0; n < conf->redirects->nelts; n++) {
        char *arg = rewrite_args(pool, entries);
        mod = apn_mod_insert_sibling(mod, "rewrite", arg);

        entries++;
    }

    return mod;
}

module AP_MODULE_DECLARE_DATA alias_module =
{
    STANDARD20_MODULE_STUFF,
    create_alias_dir_config,       /* dir config creater */
    merge_alias_dir_config,        /* dir merger --- default is to override */
    create_alias_config,           /* server config */
    merge_alias_config,            /* merge server configs */
    alias_cmds,                    /* command apr_table_t */
    register_hooks,                /* register hooks */

    convert_alias_in_dir,          /* convert the dir */
    convert_alias_in_server        /* convert the server */
};
