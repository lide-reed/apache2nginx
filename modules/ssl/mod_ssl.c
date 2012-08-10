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

/*                      _             _
 *  _ __ ___   ___   __| |    ___ ___| |  mod_ssl
 * | '_ ` _ \ / _ \ / _` |   / __/ __| |  Apache Interface to OpenSSL
 * | | | | | | (_) | (_| |   \__ \__ \ |
 * |_| |_| |_|\___/ \__,_|___|___/___/_|
 *                      |_____|
 *  mod_ssl.c
 *  Apache API interface structures
 */

#include "ssl_private.h"
#include "mod_ssl.h"
#include "util_md5.h"
#include <assert.h>

/*
 *  the table of configuration directives we provide
 */

#define SSL_CMD_ALL(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF|OR_AUTHCFG, desc),

#define SSL_CMD_SRV(name, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, RSRC_CONF, desc),

#define SSL_CMD_DIR(name, type, args, desc) \
        AP_INIT_##args("SSL"#name, ssl_cmd_SSL##name, \
                       NULL, OR_##type, desc),

#define AP_END_CMD { NULL }

const char ssl_valid_ssl_mutex_string[] =
    "Valid SSLMutex mechanisms are: `none', `default'"
#if APR_HAS_FLOCK_SERIALIZE
    ", `flock:/path/to/file'"
#endif
#if APR_HAS_FCNTL_SERIALIZE
    ", `fcntl:/path/to/file'"
#endif
#if APR_HAS_SYSVSEM_SERIALIZE && !defined(PERCHILD_MPM)
    ", `sysvsem'"
#endif
#if APR_HAS_POSIXSEM_SERIALIZE
    ", `posixsem'"
#endif
#if APR_HAS_PROC_PTHREAD_SERIALIZE
    ", `pthread'"
#endif
#if APR_HAS_FLOCK_SERIALIZE || APR_HAS_FCNTL_SERIALIZE
    ", `file:/path/to/file'"
#endif
#if (APR_HAS_SYSVSEM_SERIALIZE && !defined(PERCHILD_MPM)) || APR_HAS_POSIXSEM_SERIALIZE
    ", `sem'"
#endif
    " ";

static const command_rec ssl_config_cmds[] = {
    /*
     * Global (main-server) context configuration directives
     */
    SSL_CMD_SRV(Mutex, TAKE1, ssl_valid_ssl_mutex_string)
    SSL_CMD_SRV(PassPhraseDialog, TAKE1,
                "SSL dialog mechanism for the pass phrase query "
                "(`builtin', `|/path/to/pipe_program`, "
                "or `exec:/path/to/cgi_program')")
    SSL_CMD_SRV(SessionCache, TAKE1,
                "SSL Session Cache storage "
                "(`none', `nonenotnull', `dbm:/path/to/file')")
#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ENGINE_INIT)
    SSL_CMD_SRV(CryptoDevice, TAKE1,
                "SSL external Crypto Device usage "
                "(`builtin', `...')")
#endif
    SSL_CMD_SRV(RandomSeed, TAKE23,
                "SSL Pseudo Random Number Generator (PRNG) seeding source "
                "(`startup|connect builtin|file:/path|exec:/path [bytes]')")

    /*
     * Per-server context configuration directives
     */
    SSL_CMD_SRV(Engine, TAKE1,
                "SSL switch for the protocol engine "
                "(`on', `off')")
    SSL_CMD_SRV(FIPS, FLAG,
                "Enable FIPS-140 mode "
                "(`on', `off')")
    SSL_CMD_ALL(CipherSuite, TAKE1,
                "Colon-delimited list of permitted SSL Ciphers "
                "(`XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(CertificateFile, TAKE1,
                "SSL Server Certificate file "
                "(`/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateKeyFile, TAKE1,
                "SSL Server Private Key file "
                "(`/path/to/file' - PEM or DER encoded)")
    SSL_CMD_SRV(CertificateChainFile, TAKE1,
                "SSL Server CA Certificate Chain file "
                "(`/path/to/file' - PEM encoded)")
    SSL_CMD_ALL(CACertificatePath, TAKE1,
                "SSL CA Certificate path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_ALL(CACertificateFile, TAKE1,
                "SSL CA Certificate file "
                "(`/path/to/file' - PEM encoded)")
    SSL_CMD_SRV(CADNRequestPath, TAKE1,
                "SSL CA Distinguished Name path "
                "(`/path/to/dir' - symlink hashes to PEM of acceptable CA names to request)")
    SSL_CMD_SRV(CADNRequestFile, TAKE1,
                "SSL CA Distinguished Name file "
                "(`/path/to/file' - PEM encoded to derive acceptable CA names to request)")
    SSL_CMD_SRV(CARevocationPath, TAKE1,
                "SSL CA Certificate Revocation List (CRL) path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_SRV(CARevocationFile, TAKE1,
                "SSL CA Certificate Revocation List (CRL) file "
                "(`/path/to/file' - PEM encoded)")
    SSL_CMD_ALL(VerifyClient, TAKE1,
                "SSL Client verify type "
                "(`none', `optional', `require', `optional_no_ca')")
    SSL_CMD_ALL(VerifyDepth, TAKE1,
                "SSL Client verify depth "
                "(`N' - number of intermediate certificates)")
    SSL_CMD_SRV(SessionCacheTimeout, TAKE1,
                "SSL Session Cache object lifetime "
                "(`N' - number of seconds)")
    SSL_CMD_SRV(Protocol, RAW_ARGS,
                "Enable or disable various SSL protocols"
                "(`[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")
    SSL_CMD_SRV(HonorCipherOrder, FLAG,
                "Use the server's cipher ordering preference")
    SSL_CMD_SRV(InsecureRenegotiation, FLAG,
                "Enable support for insecure renegotiation")
    SSL_CMD_ALL(UserName, TAKE1,
                "Set user name to SSL variable value")
    SSL_CMD_SRV(StrictSNIVHostCheck, FLAG,
                "Strict SNI virtual host checking")

    /*
     * Proxy configuration for remote SSL connections
     */
    SSL_CMD_SRV(ProxyEngine, FLAG,
                "SSL switch for the proxy protocol engine "
                "(`on', `off')")
    SSL_CMD_SRV(ProxyProtocol, RAW_ARGS,
               "SSL Proxy: enable or disable SSL protocol flavors "
               "(`[+-][SSLv2|SSLv3|TLSv1] ...' - see manual)")
    SSL_CMD_SRV(ProxyCipherSuite, TAKE1,
               "SSL Proxy: colon-delimited list of permitted SSL ciphers "
               "(`XXX:...:XXX' - see manual)")
    SSL_CMD_SRV(ProxyVerify, TAKE1,
               "SSL Proxy: whether to verify the remote certificate "
               "(`on' or `off')")
    SSL_CMD_SRV(ProxyVerifyDepth, TAKE1,
               "SSL Proxy: maximum certificate verification depth "
               "(`N' - number of intermediate certificates)")
    SSL_CMD_SRV(ProxyCACertificateFile, TAKE1,
               "SSL Proxy: file containing server certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCACertificatePath, TAKE1,
               "SSL Proxy: directory containing server certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCARevocationPath, TAKE1,
                "SSL Proxy: CA Certificate Revocation List (CRL) path "
                "(`/path/to/dir' - contains PEM encoded files)")
    SSL_CMD_SRV(ProxyCARevocationFile, TAKE1,
                "SSL Proxy: CA Certificate Revocation List (CRL) file "
                "(`/path/to/file' - PEM encoded)")
    SSL_CMD_SRV(ProxyMachineCertificateFile, TAKE1,
               "SSL Proxy: file containing client certificates "
               "(`/path/to/file' - PEM encoded certificates)")
    SSL_CMD_SRV(ProxyMachineCertificatePath, TAKE1,
               "SSL Proxy: directory containing client certificates "
               "(`/path/to/dir' - contains PEM encoded certificates)")
    SSL_CMD_SRV(ProxyCheckPeerExpire, FLAG,
                "SSL Proxy: check the peers certificate expiration date")
    SSL_CMD_SRV(ProxyCheckPeerCN, FLAG,
                "SSL Proxy: check the peers certificate CN")

    /*
     * Per-directory context configuration directives
     */
    SSL_CMD_DIR(Options, OPTIONS, RAW_ARGS,
               "Set one or more options to configure the SSL engine"
               "(`[+-]option[=value] ...' - see manual)")
    SSL_CMD_DIR(RequireSSL, AUTHCFG, NO_ARGS,
               "Require the SSL protocol for the per-directory context "
               "(no arguments)")
    SSL_CMD_DIR(Require, AUTHCFG, RAW_ARGS,
               "Require a boolean expression to evaluate to true for granting access"
               "(arbitrary complex boolean expression - see manual)")
    SSL_CMD_DIR(RenegBufferSize, AUTHCFG, TAKE1,
                "Configure the amount of memory that will be used for buffering the "
                "request body if a per-location SSL renegotiation is required due to "
                "changed access control requirements")

    /* Deprecated directives. */
    AP_INIT_RAW_ARGS("SSLLog", ap_set_deprecated, NULL, OR_ALL,
      "SSLLog directive is no longer supported - use ErrorLog."),
    AP_INIT_RAW_ARGS("SSLLogLevel", ap_set_deprecated, NULL, OR_ALL,
      "SSLLogLevel directive is no longer supported - use LogLevel."),

    AP_END_CMD
};

static SSLConnRec *ssl_init_connection_ctx(conn_rec *c)
{
#if 0
    SSLConnRec *sslconn = myConnConfig(c);

    if (sslconn) {
        return sslconn;
    }

    sslconn = apr_pcalloc(c->pool, sizeof(*sslconn));

    sslconn->server = c->base_server;

    myConnConfigSet(c, sslconn);

    return sslconn;
#endif

    return NULL;
}

int ssl_proxy_enable(conn_rec *c)
{
#if 0
    SSLSrvConfigRec *sc;

    SSLConnRec *sslconn = ssl_init_connection_ctx(c);
    sc = mySrvConfig(sslconn->server);

    if (!sc->proxy_enabled) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "SSL Proxy requested for %s but not enabled "
                      "[Hint: SSLProxyEngine]", sc->vhost_id);

        return 0;
    }

    sslconn->is_proxy = 1;
    sslconn->disabled = 0;
#endif

    return 1;
}

int ssl_engine_disable(conn_rec *c)
{
#if 0
    SSLSrvConfigRec *sc;

    SSLConnRec *sslconn = myConnConfig(c);

    if (sslconn) {
        sc = mySrvConfig(sslconn->server);
    }
    else {
        sc = mySrvConfig(c->base_server);
    }
    if (sc->enabled == SSL_ENABLED_FALSE) {
        return 0;
    }

    sslconn = ssl_init_connection_ctx(c);

    sslconn->disabled = 1;
#endif

    return 1;
}

int ssl_init_ssl_connection(conn_rec *c)
{
#if 0
    SSLSrvConfigRec *sc;
    SSL *ssl;
    SSLConnRec *sslconn = myConnConfig(c);
    char *vhost_md5;
    modssl_ctx_t *mctx;
    server_rec *server;

    if (!sslconn) {
        sslconn = ssl_init_connection_ctx(c);
    }
    server = sslconn->server;
    sc = mySrvConfig(server);

    /*
     * Seed the Pseudo Random Number Generator (PRNG)
     */
    ssl_rand_seed(server, c->pool, SSL_RSCTX_CONNECT, "");

    mctx = sslconn->is_proxy ? sc->proxy : sc->server;

    /*
     * Create a new SSL connection with the configured server SSL context and
     * attach this to the socket. Additionally we register this attachment
     * so we can detach later.
     */
    if (!(ssl = SSL_new(mctx->ssl_ctx))) {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "Unable to create a new SSL connection from the SSL "
                      "context");
        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, server);

        c->aborted = 1;

        return DECLINED; /* XXX */
    }

    vhost_md5 = ap_md5_binary(c->pool, (unsigned char *)sc->vhost_id,
                              sc->vhost_id_len);

    if (!SSL_set_session_id_context(ssl, (unsigned char *)vhost_md5,
                                    APR_MD5_DIGESTSIZE*2))
    {
        ap_log_cerror(APLOG_MARK, APLOG_ERR, 0, c,
                      "Unable to set session id context to `%s'", vhost_md5);
        ssl_log_ssl_error(APLOG_MARK, APLOG_ERR, server);

        c->aborted = 1;

        return DECLINED; /* XXX */
    }

    SSL_set_app_data(ssl, c);
    SSL_set_app_data2(ssl, NULL); /* will be request_rec */

    sslconn->ssl = ssl;

    /*
     *  Configure callbacks for SSL connection
     */
    SSL_set_tmp_rsa_callback(ssl, ssl_callback_TmpRSA);
    SSL_set_tmp_dh_callback(ssl,  ssl_callback_TmpDH);

    SSL_set_verify_result(ssl, X509_V_OK);

    ssl_io_filter_init(c, ssl);

#endif
    return APR_SUCCESS;
}

#if 0
static const char *ssl_hook_http_scheme(const request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc->enabled == SSL_ENABLED_FALSE || sc->enabled == SSL_ENABLED_OPTIONAL) {
        return NULL;
    }

    return "https";
}
#endif

#if 0
static apr_port_t ssl_hook_default_port(const request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc->enabled == SSL_ENABLED_FALSE || sc->enabled == SSL_ENABLED_OPTIONAL) {
        return 0;
    }

    return 443;
}
#endif

#if 0
static int ssl_hook_pre_connection(conn_rec *c, void *csd)
{
    SSLSrvConfigRec *sc;
    SSLConnRec *sslconn = myConnConfig(c);

    if (sslconn) {
        sc = mySrvConfig(sslconn->server);
    }
    else {
        sc = mySrvConfig(c->base_server);
    }
    /*
     * Immediately stop processing if SSL is disabled for this connection
     */
    if (!(sc && (sc->enabled == SSL_ENABLED_TRUE ||
                 (sslconn && sslconn->is_proxy))))
    {
        return DECLINED;
    }

    /*
     * Create SSL context
     */
    if (!sslconn) {
        sslconn = ssl_init_connection_ctx(c);
    }

    if (sslconn->disabled) {
        return DECLINED;
    }

    /*
     * Remember the connection information for
     * later access inside callback functions
     */

    ap_log_cerror(APLOG_MARK, APLOG_INFO, 0, c,
                  "Connection to child %ld established "
                  "(server %s)", c->id, sc->vhost_id);

    return ssl_init_ssl_connection(c);
}
#endif

#if 0
static void ssl_hook_Insert_Filter(request_rec *r)
{
    SSLSrvConfigRec *sc = mySrvConfig(r->server);

    if (sc->enabled == SSL_ENABLED_OPTIONAL) {
        ap_add_output_filter("UPGRADE_FILTER", NULL, r, r->connection);
    }
}
#endif

/*
 *  the module registration phase
 */

static void ssl_register_hooks(apr_pool_t *p)
{
    /* ssl_hook_ReadReq needs to use the BrowserMatch settings so must
     * run after mod_setenvif's post_read_request hook. */
    static const char *pre_prr[] = { "mod_setenvif.c", NULL };

    //ap_hook_pre_connection(ssl_hook_pre_connection,NULL,NULL, APR_HOOK_MIDDLE);
    ap_hook_test_config   (ssl_hook_ConfigTest,    NULL,NULL, APR_HOOK_MIDDLE);
    //ap_hook_default_port  (ssl_hook_default_port,  NULL,NULL, APR_HOOK_MIDDLE);

    APR_REGISTER_OPTIONAL_FN(ssl_proxy_enable);
    APR_REGISTER_OPTIONAL_FN(ssl_engine_disable);
}



static int SSL_CACHE_NAME_NUM = 0;

static void *
ssl_convert_perdir(apr_pool_t *pool, cmd_parms *parms, ap_conf_vector_t* v)
{
    apn_module_t *mod = NULL;


    return mod;
}

static void *
ssl_convert_server(apr_pool_t *pool, cmd_parms *parms, ap_conf_vector_t* v)
{
    apn_module_t *mod = NULL;
    SSLSrvConfigRec *sconf = ap_get_module_config(v, &ssl_module);

    /** SSLEngine */
    if (sconf->cmd_SSLEngine == TRUE) {
        if (sconf->enabled == SSL_ENABLED_TRUE || sconf->enabled == SSL_ENABLED_OPTIONAL) {
            mod = apn_mod_insert_sibling(mod, "ssl", "on");
        } else {
            mod = apn_mod_insert_sibling(mod, "ssl", "off");
        }
    }

    /** SSLProtocol */
    char *protocols = "";
    if (sconf->cmd_SSLProtocol == TRUE) {
        if (sconf->server->protocol & SSL_PROTOCOL_SSLV2) {
            protocols = apr_pstrcat(pool, protocols, " SSLv2", NULL);
        }
        if (sconf->server->protocol & SSL_PROTOCOL_SSLV3) {
            protocols = apr_pstrcat(pool, protocols, " SSLv3", NULL);
        }
        if (sconf->server->protocol & SSL_PROTOCOL_TLSV1) {
            protocols = apr_pstrcat(pool, protocols, " TLSv1", NULL);
        }
        if (strlen(protocols) != 0) {
            mod = apn_mod_insert_sibling(mod, "ssl_protocols", protocols+1);
        }
    }

    /** SSLCACertificateFile */
    char *ca_cert_file = sconf->server->auth.ca_cert_file;
    if (ca_cert_file != NULL) {
        mod = apn_mod_insert_sibling(mod, "ssl_client_certificate", ca_cert_file);
    }

    /** SSLCARevocationFile */
    if (sconf->server->crl_file != NULL) {
        mod = apn_mod_insert_sibling(mod, "ssl_crl", sconf->server->crl_file);
    }

    /** SSLCertificateChainFile */
    if (sconf->server->cert_chain != NULL) {
        mod = apn_mod_insert_sibling(mod, "ssl_certificate", sconf->server->cert_chain);
    }

    /** SSLCertificateFile */
    if (sconf->server->pks->cert_files != NULL && *sconf->server->pks->cert_files != NULL) {
        mod = apn_mod_insert_sibling(mod, "ssl_certificate", *sconf->server->pks->cert_files);
    }

    /** SSLCertificateKeyFile */
    if (sconf->server->pks->key_files != NULL && *sconf->server->pks->key_files != NULL) {
        mod = apn_mod_insert_sibling(mod, "ssl_certificate_key", *sconf->server->pks->key_files);
    }

    /** SSLCipherSuite */
    if (sconf->server->auth.cipher_suite != NULL) {
        mod = apn_mod_insert_sibling(mod, "ssl_ciphers", sconf->server->auth.cipher_suite);
    }

    /** SSLHonorCipherOrder */
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
    if (sconf->cipher_server_pref == TRUE) {
        mod = apn_mod_insert_sibling(mod, "ssl_prefer_server_ciphers", "on");
    } else if (sconf->cipher_server_pref == FALSE) {
        mod = apn_mod_insert_sibling(mod, "ssl_prefer_server_ciphers", "off");
    }
#endif

    /** SSLInsecureRenegotiation */
    /* not supported by Nginx */

    /** SSLSessionCache */
    SSLModConfigRec *mc = sconf->mc;
    if (mc->nSessionCacheMode == SSL_SCMODE_NONE) {
        mod = apn_mod_insert_sibling(mod, "ssl_session_cache", "none");
    } else if (mc->nSessionCacheMode == SSL_SCMODE_NONE_NOT_NULL) {
        mod = apn_mod_insert_sibling(mod, "ssl_session_cache", "off");
    } else if (mc->nSessionCacheMode == SSL_SCMODE_DBM) {
        // not supported in Nginx.
    } else if (mc->nSessionCacheMode == SSL_SCMODE_SHMCB) {
        char *ssl_cache_name = NULL;
        if (SSL_CACHE_NAME_NUM == 0) {
            ssl_cache_name = "SSL";
            SSL_CACHE_NAME_NUM++;
        } else {
            char *temp_num = apr_itoa(pool, SSL_CACHE_NAME_NUM++);
            ssl_cache_name = apr_pstrcat(pool, "SSL", temp_num, NULL);
        }

        int cache_size = mc->nSessionCacheDataSize;
        char *cache_size_str = NULL;
        if (cache_size == 1024*512) {
            cache_size_str = "512k";
        } else {
            cache_size_str = apr_itoa(pool, cache_size);
        }

        char *args = apr_pstrcat(pool, "shared:", ssl_cache_name, ":", cache_size_str, NULL);
        mod = apn_mod_insert_sibling(mod, "ssl_session_cache", args);
    } else if (mc->nSessionCacheMode == SSL_SCMODE_DC) {
        // dc: not supported in Nginx.
    }

    /** SSLSessionCacheTimeout */
    if (sconf->session_cache_timeout != UNSET) {
        char *args = apr_itoa(pool, sconf->session_cache_timeout);
        mod = apn_mod_insert_sibling(mod, "ssl_session_timeout", args);
    }

    /** SSLVerifyClient */
    if (sconf->server->auth.verify_mode == SSL_CVERIFY_NONE) {
        mod = apn_mod_insert_sibling(mod, "ssl_verify_client", "off");
    } else if (sconf->server->auth.verify_mode == SSL_CVERIFY_OPTIONAL) {
        mod = apn_mod_insert_sibling(mod, "ssl_verify_client", "optional");
    } else if (sconf->server->auth.verify_mode == SSL_CVERIFY_REQUIRE) {
        mod = apn_mod_insert_sibling(mod, "ssl_verify_client", "on");
    } else if (sconf->server->auth.verify_mode == SSL_CVERIFY_OPTIONAL_NO_CA) {
        // not supported in Nginx
    }

    /** SSLVerifyDepth */
    if (sconf->server->auth.verify_depth != UNSET) {
        char *args = apr_itoa(pool, sconf->server->auth.verify_depth);
        mod = apn_mod_insert_sibling(mod, "ssl_verify_depth", args);
    }

    /** SSLPassPhraseDialog */
    char *comment_pass_phrase = "This directive isn't supported by Nginx official version. Refer to the patch: http://forum.nginx.org/read.php?2,214641,229163";
    if (sconf->server->pphrase_dialog_type == SSL_PPTYPE_BUILTIN) {
        mod = apn_mod_insert_sibling(mod, "ssl_pass_phrase_dialog", "builtin");
        apn_mod_add_comment(mod, comment_pass_phrase); 
    } else if (sconf->server->pphrase_dialog_type == SSL_PPTYPE_FILTER) {
        char *args = apr_pstrcat(pool, "exec:", sconf->server->pphrase_dialog_path, NULL);
        mod = apn_mod_insert_sibling(mod, "ssl_pass_phrase_dialog", args);
        apn_mod_add_comment(mod, comment_pass_phrase); 
    }

    return mod;
}

module AP_MODULE_DECLARE_DATA ssl_module = {
    STANDARD20_MODULE_STUFF,
    ssl_config_perdir_create,   /* create per-dir    config structures */
    ssl_config_perdir_merge,    /* merge  per-dir    config structures */
    ssl_config_server_create,   /* create per-server config structures */
    ssl_config_server_merge,    /* merge  per-server config structures */
    ssl_config_cmds,            /* table of configuration directives   */
    ssl_register_hooks,         /* register hooks */

    ssl_convert_perdir,         /* */
    ssl_convert_server          /* */
};
