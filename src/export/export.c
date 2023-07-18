#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>

#include <jansson.h>

#include "export.h"
#include "queue.h"
#include "../logging.h"

static int g_running = 1;
static pthread_t g_thread;

typedef struct {
    Queue* queue;
    int export_rate_seconds;  // How much time to wait until flush
    uint32_t export_treshold;  // How many items in queue to trigger a flush at end
} ExportRoutineArgs;

static int append_to_json_array(json_t* array, const MacNtp* data) {
    json_t* item = json_pack(
        "{s:s,s:i}",
        "source_mac",
        data->source_mac,
        "ntp_version",
        data->ntp_version
    );

    if (item == NULL) {
        return -1;
    }

    if (json_array_append_new(array, item) < 0) {
        return -1;
    }

    return 0;
}

static void flush_and_export(Queue* queue) {
    // Don't do anything, if there is no data to export
    if (queue_is_empty(queue)) {
        return;
    }

    // Create root json object
    json_t* object = json_pack("{s:[]}", "packets");

    if (object == NULL) {
        goto err_export;
    }

    json_t* array = json_object_get(object, "packets");

    if (array == NULL) {
        goto err_export;
    }

    // Append all the items
    while (!queue_is_empty(queue)) {
        MacNtp data;
        queue_dequeue(queue, &data);  // Error not handled, not needed

        if (append_to_json_array(array, &data) < 0) {
            goto err_export;
        }
    }

    // Dump to file
    const char* file_name = "exported.json";
    FILE* file = fopen(file_name, "w");

    if (file == NULL) {
        goto err_export;
    }

    if (json_dumpf(object, file, 0) < 0) {  // This overrides the previous contents
        goto err_export;
    }

    json_decref(object);

    if (fclose(file) != 0) {
        goto err_export;
    }

    log_print("Exported to `%s`\n", file_name);

    return;

err_export:
    log_print("Exporting failed\n");
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
        // flush_and_export may be called even if there is no data

        if (!g_running || wait_and_check(&time_start, export_args)) {
            flush_and_export(queue);
        }
    }

    if (queue_size(queue) > export_args->export_treshold) {
        flush_and_export(queue);
    }

    return NULL;
}

int export_start_thread(Queue* queue, int export_rate_seconds, uint32_t export_treshold) {
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

int export_stop_thread(void) {
    g_running = 0;

    const int result = pthread_join(g_thread, NULL);

    if (result != 0) {
        printf("Could not join export thread: %d", result);
        return -1;
    }

    return 0;
}
