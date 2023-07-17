#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/queue.h>
#include <pthread.h>

typedef struct {
    char source_mac[18];  // TODO hash
    uint8_t ntp_version;
} MacNtp;

typedef void(*QueueTraverse)(MacNtp*);

struct QueueEntry {
    MacNtp data;
    TAILQ_ENTRY(QueueEntry) entries;
};

TAILQ_HEAD(QueueHead, QueueEntry);

typedef struct {
    struct QueueHead head;
    uint32_t size;
    pthread_mutex_t mutex;
} Queue;

int queue_initialize(Queue* queue);
void queue_uninitialize(Queue* queue);
int queue_enqueue(Queue* queue, MacNtp* item);
int queue_dequeue(Queue* queue, MacNtp* out_item);
bool queue_is_empty(Queue* queue);
uint32_t queue_size(Queue* queue);

#endif
