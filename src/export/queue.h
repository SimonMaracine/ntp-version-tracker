#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <pthread.h>

/**
 * Struct for temporarily storing data (for later exporting).
*/
typedef struct {
    char source_mac[18];  // TODO hash
    uint8_t ntp_version;
} MacNtp;

struct QueueEntry {
    MacNtp data;
    TAILQ_ENTRY(QueueEntry) entries;
};

TAILQ_HEAD(QueueHead, QueueEntry);

/**
 * The queue structure, holding MacNtp items.
 *
 * @see MacNtp
*/
typedef struct {
    struct QueueHead head;
    uint32_t size;
    pthread_mutex_t mutex;
} Queue;

/**
 * Initialize the queue.
 *
 * @param queue a pointer to the queue object
 * @return 0 on success, -1 on error
 * @see Queue
*/
int queue_initialize(Queue* queue);

/**
 * Uninitialize and deallocate the queue.
 *
 * @param queue a pointer to the queue object
 * @see Queue
*/
void queue_uninitialize(Queue* queue);

/**
 * Append an element to the front of the queue.
 *
 * @param queue a pointer to the queue object
 * @param item a pointer to the data item
 * @return 0 on success, -1 on error
 * @see Queue
 * @see MacNtp
*/
int queue_enqueue(Queue* queue, MacNtp* item);

/**
 * Remove an element from the back of the queue and return it.
 *
 * @param queue a pointer to the queue object
 * @param out_item a pointer to where the removed item should be written
 * @return 0 on success, -1 on error
 * @see Queue
 * @see MacNtp
*/
int queue_dequeue(Queue* queue, MacNtp* out_item);

/**
 * Check if the queue is empty.
 *
 * @param queue a pointer to the queue object
 * @return true if the queue is empty, false otherwise
 * @see Queue
*/
bool queue_is_empty(Queue* queue);

/**
 * Get the queue size.
 *
 * @param queue a pointer to the queue object
 * @return the number of items in the queue
 * @see Queue
*/
uint32_t queue_size(Queue* queue);

#endif
