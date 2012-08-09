dnl  Copyright 2001-2005 The Apache Software Foundation or its licensors, as
dnl  applicable.
dnl  Licensed under the Apache License, Version 2.0 (the "License");
dnl  you may not use this file except in compliance with the License.
dnl  You may obtain a copy of the License at
dnl 
dnl       http://www.apache.org/licenses/LICENSE-2.0
dnl 
dnl  Unless required by applicable law or agreed to in writing, software
dnl  distributed under the License is distributed on an "AS IS" BASIS,
dnl  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl  See the License for the specific language governing permissions and
dnl  limitations under the License.

dnl #  start of module specific part
APACHE_MODPATH_INIT(ssl)

dnl #  list of module object files
ssl_objs="dnl
mod_ssl.lo dnl
ssl_engine_config.lo dnl
ssl_expr.lo dnl
ssl_expr_parse.lo dnl
ssl_expr_scan.lo dnl
ssl_util.lo dnl
"
dnl #  hook module into the Autoconf mechanism (--enable-ssl option)
APACHE_MODULE(ssl, [SSL/TLS support (mod_ssl)], $ssl_objs, , most)

# Ensure that other modules can pick up mod_ssl.h
APR_ADDTO(INCLUDES, [-I\$(top_srcdir)/$modpath_current])

dnl #  end of module specific part
APACHE_MODPATH_FINISH

