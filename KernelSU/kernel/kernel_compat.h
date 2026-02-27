#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
/* copy_from_user_nofault and strncpy_from_user_nofault don't exist before ~5.x.
 * Provide simple fallback wrappers. */
static inline long copy_from_user_nofault(void *to, const void __user *from,
                                          unsigned long count)
{
    if (!access_ok(VERIFY_READ, from, count))
        return -EFAULT;
    return __copy_from_user_inatomic(to, from, count);
}

static inline long copy_to_user_nofault(void __user *to, const void *from,
                                        unsigned long count)
{
    if (!access_ok(VERIFY_WRITE, to, count))
        return -EFAULT;
    return __copy_to_user_inatomic(to, from, count);
}

static inline long strncpy_from_user_nofault(char *dst,
                                             const void __user *unsafe_addr,
                                             long count)
{
    if (!access_ok(VERIFY_READ, unsafe_addr, 1))
        return -EFAULT;
    return strncpy_from_user(dst, unsafe_addr, count);
}
#endif

/*
 * ksu_copy_from_user_retry
 * try nofault copy first, if it fails, try with plain
 * paramters are the same as copy_from_user
 * 0 = success
 */
static long ksu_copy_from_user_retry(void *to, const void __user *from,
                                     unsigned long count)
{
    long ret = copy_from_user_nofault(to, from, count);
    if (likely(!ret))
        return ret;

    // we faulted! fallback to slow path
    return copy_from_user(to, from, count);
}

#endif
