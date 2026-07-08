#ifndef UTILS_H
#define UTILS_H

#include <signal.h>
#include <stddef.h>

extern volatile sig_atomic_t exiting;

void on_signal(int sig);
void iso_timestamp(char *buf, size_t len);

#endif
