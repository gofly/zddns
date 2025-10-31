#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <cjson/cJSON.h>

#include "natmap.h"

// Helper function to read a file's content into a string.
// The caller is responsible for freeing the returned buffer.
static char* read_file_to_string(const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = (char*)malloc(len + 1);
    if (!buf) {
        fclose(f);
        fprintf(stderr, "malloc failed\n");
        return NULL;
    }

    if (fread(buf, 1, len, f) != (size_t)len) {
        fclose(f);
        free(buf);
        fprintf(stderr, "fread failed for %s\n", filepath);
        return NULL;
    }

    fclose(f);
    buf[len] = '\0';
    return buf;
}

int find_natmap_entry(const char *natmap_dir, const char *protocol, int inner_port, char *out_ip, size_t ip_buf_size, int *out_port) {
    DIR *dir = opendir(natmap_dir);
    if (!dir) {
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf), "opendir failed for %s", natmap_dir);
        perror(err_buf);
        return -1;
    }

    struct dirent *entry;
    int found = 1; // Not found by default

    while ((entry = readdir(dir)) != NULL) {
        // Check if it's a .json file
        const char *dot = strrchr(entry->d_name, '.');
        if (!dot || strcmp(dot, ".json") != 0) {
            continue;
        }

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/%s", natmap_dir, entry->d_name);

        struct stat st;
        if (stat(filepath, &st) == -1 || !S_ISREG(st.st_mode)) {
            continue; // Skip directories or other non-regular files
        }

        char *file_content = read_file_to_string(filepath);
        if (!file_content) {
            continue; // Error reading file, try next
        }

        cJSON *root = cJSON_Parse(file_content);
        free(file_content);

        if (!root) {
            fprintf(stderr, "Failed to parse JSON from %s\n", filepath);
            continue;
        }

        const cJSON *proto_item = cJSON_GetObjectItemCaseSensitive(root, "protocol");
        const cJSON *inner_port_item = cJSON_GetObjectItemCaseSensitive(root, "inner_port");

        if (cJSON_IsString(proto_item) && (proto_item->valuestring != NULL) &&
            cJSON_IsNumber(inner_port_item)) {

            if (strcmp(proto_item->valuestring, protocol) == 0 &&
                inner_port_item->valueint == inner_port) {

                const cJSON *ip_item = cJSON_GetObjectItemCaseSensitive(root, "ip");
                const cJSON *port_item = cJSON_GetObjectItemCaseSensitive(root, "port");

                if (cJSON_IsString(ip_item) && (ip_item->valuestring != NULL) &&
                    cJSON_IsNumber(port_item)) {

                    strncpy(out_ip, ip_item->valuestring, ip_buf_size - 1);
                    out_ip[ip_buf_size - 1] = '\0'; // Ensure null termination
                    *out_port = port_item->valueint;

                    found = 0; // Found!
                    cJSON_Delete(root);
                    break; // Exit the loop
                }
            }
        }

        cJSON_Delete(root);
    }

    closedir(dir);
    return found;
}