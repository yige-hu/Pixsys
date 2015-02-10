#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/time.h>
#include <asm/uaccess.h>

/* Macros used to get local time */

#define SECS_PER_HOUR   (60 * 60)
#define SECS_PER_DAY    (SECS_PER_HOUR * 24)
#define isleap(year) \
	((year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0))
#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))

struct vtm
{
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
};

int timezone;

int epoch2time(const time_t * t, long int offset, struct vtm *tp)
{
	static const unsigned short int mon_yday[2][13] = {
		/* Normal years.  */
		{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
		/* Leap years.  */
		{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}
	};

	long int days, rem, y;
	const unsigned short int *ip;

	days = *t / SECS_PER_DAY;
	rem = *t % SECS_PER_DAY;
	rem += offset;
	while (rem < 0) {
		rem += SECS_PER_DAY;
		--days;
	}
	while (rem >= SECS_PER_DAY) {
		rem -= SECS_PER_DAY;
		++days;
	}
	tp->tm_hour = rem / SECS_PER_HOUR;
	rem %= SECS_PER_HOUR;
	tp->tm_min = rem / 60;
	tp->tm_sec = rem % 60;
	y = 1970;

	while (days < 0 || days >= (isleap(y) ? 366 : 365)) {
		long int yg = y + days / 365 - (days % 365 < 0);
		days -= ((yg - y) * 365 + LEAPS_THRU_END_OF(yg - 1)
		    - LEAPS_THRU_END_OF(y - 1));
		y = yg;
	}
	tp->tm_year = y - 1900;
	if (tp->tm_year != y - 1900)
		return 0;
	ip = mon_yday[isleap(y)];
	for (y = 11; days < (long int) ip[y]; --y)
		continue;
	days -= ip[y];
	tp->tm_mon = y;
	tp->tm_mday = days + 1;
	return 1;
}

/*
 *  Get current date & time
 */

void get_time(char *date_time)
{
	struct timeval tv;
	time_t t;
	struct vtm tm;

	do_gettimeofday(&tv);
	t = (time_t) tv.tv_sec;

	epoch2time(&t, timezone, &tm);

	sprintf(date_time, "%.2d/%.2d/%d-%.2d:%.2d:%.2d", tm.tm_mday,
	    tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min,
	    tm.tm_sec);
}
