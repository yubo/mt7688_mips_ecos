#ifndef __TRAFFICD_INT_H
#define __TRAFFICD_INT_H

#ifdef __ECOS
#include <linux/types.h>

#define __be32 uint32_t

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define INT32_MIN    (-(int32_t)(2147483647)-1)
#define INT32_MAX    ((int32_t)(2147483647))
#define INT64_MIN    (-(int64_t)(9223372036854775807)-1)
#define INT64_MAX    ((int64_t)(9223372036854775807))
#define PRId64 "lld"
#define SCNd64 "lld"
#ifndef uint64_t
#define uint64_t cyg_uint64
#endif
#ifndef int64_t
#define int64_t cyg_int64
#endif

#endif

#endif

