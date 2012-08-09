/** 
 * @file apn_debug.h
 * @brief include some usefull global definition and functions.
 * @author lide, lide@nhn.com
 * @date 2012-04-24
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
