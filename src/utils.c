#include "../include/utils.h"
#include <time.h>

volatile sig_atomic_t exiting;

void on_signal(int sig) { (void)sig; exiting = 1; }

void iso_timestamp(char *buf, size_t len)
{
	time_t now = time(NULL);
	struct tm tm;
	localtime_r(&now, &tm);
	strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
}
