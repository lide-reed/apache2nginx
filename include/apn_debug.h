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
 * Platform Development Team 2
 * 9th Floor, Tower B, Fairmont Tower,
 * No.33 Guangshun North Avenue
 * Wangjing, Chaoyang District
 * Beijing, China, 100102
 * www.nhncorp.cn | cn.naver.com
 *
 * Written by: Reed Lee <mailtolide@sina.com>
 * Copyright (C) 2012, NHN China Corp. 
 * All rights reserved.
 *
 */

#ifndef APN_DEBUG_H
#define APN_DEBUG_H

#include "apr.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define    APN_ERR        0    /* error conditions */
#define    APN_WARNING    1    /* warning conditions */
#define    APN_INFO    2    /* informational */
#define    APN_DEBUG    3    /* debug-level messages */

#define    APN_DEBUG_LEVELMASK    3    /* mask off the level value */
#define    APN_IS_DEBUG_LEVEL(x)    ( ((x)==APN_ERR) || \
                                  ((x)==APN_WARNING) || \
                                  ((x)==APN_INFO) || \
                                  ((x)==APN_DEBUG)  \
                                )

#ifndef DEFAULT_DEBUG_LEVEL
#define DEFAULT_DEBUG_LEVEL    APN_WARNING
#endif

#define APN_FL_MARK    __FILE__,__LINE__

AP_DECLARE(void) apn_error(const char *fmt, ...)  ;
AP_DECLARE(void) apn_warning(const char *fmt, ...);
AP_DECLARE(void) apn_info(const char *fmt, ...);
AP_DECLARE(void) apn_debug(const char *fmt, ...);
AP_DECLARE(int)  apn_get_debug_level(void);
AP_DECLARE(void) apn_set_debug_level(int level);

#ifdef __cplusplus
}
#endif

#endif    /* !APN_DEBUG_H */
/** @} */
