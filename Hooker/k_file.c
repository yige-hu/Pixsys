#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>

#include "k_file.h"

int write_to_file(char *logfile, char *buf, int size)
{
	mm_segment_t old_fs;
        struct file *f = NULL;
	int ret = 0;

        old_fs = get_fs();
	set_fs(get_ds());

	BEGIN_ROOT
        f = filp_open(logfile, O_CREAT | O_APPEND, 00600);
        if (IS_ERR(f)) {
                printk("Error %ld opening %s\n", -PTR_ERR(f), logfile);
		set_fs(old_fs);
		END_ROOT

                ret = -1;
        } else {
                if (WRITABLE(f)) {
                        _write(f, buf, size);
		}
                else {
                        printk("%s does not have a write method\n", logfile);
			set_fs(old_fs);
			END_ROOT
			
                        ret = -1;
                }

                if ((ret = filp_close(f,NULL)))
                        printk("Error %d closing %s\n", -ret, logfile);
        }
        
	set_fs(old_fs);
	END_ROOT
		
        return ret;
}

