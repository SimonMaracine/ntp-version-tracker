#include <stdbool.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <pthread.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>

#include "queue.h"

static void lock(pthread_mutex_t* mutex) {
    // Try three times with 10 ms in between

    for (unsigned int i = 0; i < 3; i++) {
        if (pthread_mutex_lock(mutex) == 0) {
            return;
        }

        usleep(10 * 1000);
    }

    abort();
}

static void unlock(pthread_mutex_t* mutex) {
    // Try three times with 10 ms in between

    for (unsigned int i = 0; i < 3; i++) {
        if (pthread_mutex_unlock(mutex) == 0) {
            return;
        }

        usleep(10 * 1000);
    }

    abort();
}

int queue_initialize(Queue* queue) {
    TAILQ_INIT(&queue->head);
    queue->size = 0;

    const int result = pthread_mutex_init(&queue->mutex, NULL);

    if (result != 0) {
        printf("Could not initialize queue mutex: %d", result);
        return -1;
    }

    return 0;
}

void queue_uninitialize(Queue* queue) {
    struct QueueEntry* ent1 = TAILQ_FIRST(&queue->head);
    struct QueueEntry* ent2 = NULL;

    while (ent1 != NULL) {
        ent2 = TAILQ_NEXT(ent1, entries);
        free(ent1);
        ent1 = ent2;
    }

    TAILQ_INIT(&queue->head);
    queue->size = 0;
}

int queue_enqueue(Queue* queue, MacNtp* item) {
    lock(&queue->mutex);

    struct QueueEntry* new_entry = malloc(sizeof(struct QueueEntry));

    if (new_entry == NULL) {
        unlock(&queue->mutex);
        return -1;
    }

    new_entry->data = *item;

    TAILQ_INSERT_HEAD(&queue->head, new_entry, entries);

    queue->size++;

    unlock(&queue->mutex);

    return 0;
}

int queue_dequeue(Queue* queue, MacNtp* out_item) {
    lock(&queue->mutex);

    struct QueueEntry* last_entry = TAILQ_LAST(&queue->head, QueueHead);

    if (last_entry == NULL) {
        unlock(&queue->mutex);
        return -1;
    }

    *out_item = last_entry->data;

    TAILQ_REMOVE(&queue->head, last_entry, entries);
    free(last_entry);

    queue->size--;

    unlock(&queue->mutex);

    return 0;
}

bool queue_is_empty(Queue* queue) {
    lock(&queue->mutex);

    const bool result = TAILQ_EMPTY(&queue->head);

    assert(result == (queue->size == 0));

    unlock(&queue->mutex);

    return result;
}

uint32_t queue_size(Queue* queue) {
    lock(&queue->mutex);

    const uint32_t result = queue->size;

    unlock(&queue->mutex);

    return result;
}
