#include <stddef.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>

#include "export.h"
#include "queue.h"

static int g_running = 1;
static pthread_t g_thread;

typedef struct {
    Queue* queue;
    int export_rate_seconds;  // How much time to wait until flush
    size_t export_treshold;  // How many items in queue to trigger a flush at end
} ExportRoutineArgs;

static int transform_in_json() {
    return 0;
}

static void flush_and_export(Queue* queue) {
    while (!queue_is_empty(queue)) {
        MacNtp data;
        queue_dequeue(queue, &data);

        printf("Stuff\n");
    }
}

static bool wait_and_check(struct timespec* time_start, const ExportRoutineArgs* export_args) {
    sleep(1);

    struct timespec time_now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &time_now);

    if (time_now.tv_sec - time_start->tv_sec > export_args->export_rate_seconds) {
        *time_start = time_now;
        return true;
    } else {
        return false;
    }
}

static void* export_routine(void* arg) {
    const ExportRoutineArgs* export_args = arg;
    Queue* queue = export_args->queue;

    struct timespec time_start;
    clock_gettime(CLOCK_MONOTONIC_RAW, &time_start);

    while (g_running) {
        // Wait a specified time before flushing

        if (!g_running || wait_and_check(&time_start, export_args)) {
            flush_and_export(queue);
        }
    }

    if (!queue_is_empty(queue) && queue_size(queue) > export_args->export_treshold) {
        flush_and_export(queue);
    }

    return NULL;
}

int export_start_thread(Queue* queue, int export_rate_seconds, size_t export_treshold) {
    static ExportRoutineArgs export_args = {0};
    export_args.queue = queue;
    export_args.export_rate_seconds = export_rate_seconds;
    export_args.export_treshold = export_treshold;

    const int result = pthread_create(&g_thread, NULL, export_routine, &export_args);

    if (result != 0) {
        printf("Could not create export thread: %d", result);
        return -1;
    }

    return 0;
}

int export_stop_thread() {
    g_running = 0;

    const int result = pthread_join(g_thread, NULL);

    if (result != 0) {
        printf("Could not join export thread: %d", result);
        return -1;
    }

    return 0;
}
