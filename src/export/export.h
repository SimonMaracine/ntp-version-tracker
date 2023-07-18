#ifndef EXPORT_H
#define EXPORT_H

#include <stdint.h>

#include "queue.h"

/**
 * Create and start the exporting thread.
 *
 * @param queue a pointer to the queue where data is written
 * @param export_rate_seconds how many seconds should pass in between data exports
 * @param export_treshold how many items must be in the queue to not drop them
 * @return 0 on success, -1 on error
 * @see Queue
*/
int export_start_thread(Queue* queue, int export_rate_seconds, uint32_t export_treshold);

/**
 * Stop the exporting thread (join).
 *
 * @return 0 on success, -1 on error
*/
int export_stop_thread(void);

#endif
