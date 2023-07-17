#ifndef EXPORT_H
#define EXPORT_H

#include <stddef.h>

#include "queue.h"

int export_start_thread(Queue* queue, int export_rate_seconds, size_t export_treshold);
int export_stop_thread();

#endif
