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

#if APR_HAVE_STDARG_H
#include <stdarg.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "apn_debug.h"

typedef struct {
    char    *t_name;
    int      t_val;
} TRANS;


static int AP_DECLARE_DATA default_level = DEFAULT_DEBUG_LEVEL;

static const TRANS priorities[] = {
    {"error",   APN_ERR},
    {"warn",    APN_WARNING},
    {"info",    APN_INFO},
    {"debug",   APN_DEBUG},
    {NULL,      -1},
};

/**
 * @param file The file in which this function is called
 * @param line The line number on which this function is called
 * @param level The level of this error message
 * @param fmt The format string
 * @param ... The arguments to use to fill out fmt.
 * @note Use APN_FL_MARK to fill out file and line
 */

static void apn_debug_internal(
        const char* file, int line,
        int level, va_list args, const char *fmt);

AP_DECLARE(void) apn_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    apn_debug_internal(APN_FL_MARK, APN_ERR, args, fmt);
    va_end(args);
}

AP_DECLARE(void) apn_warning(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    apn_debug_internal(APN_FL_MARK, APN_WARNING, args, fmt);
    va_end(args);
}

AP_DECLARE(void) apn_info(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    apn_debug_internal(APN_FL_MARK, APN_INFO, args,fmt);
    va_end(args);
}

AP_DECLARE(void) apn_debug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    apn_debug_internal(APN_FL_MARK, APN_DEBUG, args, fmt);
    va_end(args);
}

AP_DECLARE(int) apn_get_debug_level(void)
{
    return default_level;
}

AP_DECLARE(void) apn_set_debug_level(int level)
{
    if (APN_IS_DEBUG_LEVEL(level)){
        default_level = level;
    }
}

static void apn_debug_internal(
        const char* file, int line,
        int level, va_list args, const char *fmt)
{
    
    if(level > default_level ){
        return;
    }
    const char *s = priorities[level].t_name;
    if (!s) return;

    printf("[%s] ", s);
    vprintf(fmt, args);
    printf("\n");
}

