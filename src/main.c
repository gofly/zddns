#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for sleep()
#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/time.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "ddns.h"
#include "natmap.h"
#include "cos.h"
#include "template.h"

// Compile: gcc -o zddns main.c ddns.c natmap.c cos.c template.c -I./cJSON -L./cJSON -lcjson -lcurl -lssl -lcrypto -lm -pthread
// Usage:
//   # run:
//   ./zddns /path/to/config.json

int start_http_server(unsigned int port);
void process_ddns(cJSON *ddns_config, const char *secret_id, const char *secret_key);
void process_natmap(cJSON *natmap_config, const char *secret_id, const char *secret_key, const char *cos_region, const char *cos_bucket);

// read file content into a string
static char* read_file_content(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, len, f) != (size_t)len) { fclose(f); free(buf); return NULL; }
    fclose(f);
    buf[len] = '\0';
    return buf;
}

// write string to file, overwriting it
static int write_to_file(const char* filepath, const char* content) {
    FILE *f = fopen(filepath, "w");
    if (!f) {
        perror("Failed to open file for writing");
        return -1;
    }
    fprintf(f, "%s", content);
    fclose(f);
    return 0;
}

// Data to be passed to the HTTP connection handler thread
typedef struct {
    int client_sock;
    cJSON *natmap_config;
} http_thread_data_t;

// Data for the background task threads
typedef struct {
    unsigned int interval;
    cJSON *config;
    const char *secret_id;  // For natmap
    const char *secret_key; // For natmap
    const char *cos_region; // For natmap
    const char *cos_bucket; // For natmap
} task_thread_data_t;

// Thread function for the DDNS task
void *ddns_thread_func(void *arg) {
    task_thread_data_t *data = (task_thread_data_t *)arg;
    if (data->interval == 0) return NULL; // Do not run if interval is 0

    while (1) {
        printf("\n--- Running DDNS Check ---\n");
        process_ddns(data->config, data->secret_id, data->secret_key);
        sleep(data->interval);
    }
}

// Thread function to handle an incoming HTTP connection
void *http_connection_thread(void *arg) {
    http_thread_data_t *thread_data = (http_thread_data_t *)arg;
    int client_sock = thread_data->client_sock;
    cJSON *natmap_config = thread_data->natmap_config;
    free(thread_data); // Free the thread data struct

    char buffer[2048] = {0};
    recv(client_sock, buffer, sizeof(buffer) - 1, 0);

    // Very basic HTTP request parsing
    char *method = strtok(buffer, " ");
    char *url = strtok(NULL, " ");

    if (method && url && strcmp(method, "GET") == 0) {
        char *query_path = strtok(url, "?"); // `strtok` modifies the string, which is fine here
        char *query_string = strtok(NULL, "");

        if (query_path && strcmp(query_path, "/api/natmap/instance") == 0) {
            int local_port = 0;
            if (query_string) {
                char *param = strstr(query_string, "local_port=");
                if (param) {
                    local_port = atoi(param + strlen("local_port="));
                }
            }

            if (local_port > 0) {
                char public_ip[40];
                int public_port;
                const char *natmap_dir = cJSON_GetStringValue(cJSON_GetObjectItem(natmap_config, "InstancePath"));
                const char *protocol = "tcp"; // Assume TCP if not specified

                int found = find_natmap_entry(natmap_dir, protocol, local_port, public_ip, sizeof(public_ip), &public_port);

                char response_body[128];
                char http_response[512];

                if (found == 0) { // Entry found
                    cJSON *response_json = cJSON_CreateObject();
                    cJSON_AddNumberToObject(response_json, "local_port", local_port);
                    cJSON_AddStringToObject(response_json, "public_ip", public_ip);
                    cJSON_AddNumberToObject(response_json, "public_port", public_port);

                    // Now, find the corresponding instance in config to get the domain
                    cJSON *instances = cJSON_GetObjectItem(natmap_config, "Instances");
                    cJSON *instance = NULL;
                    cJSON_ArrayForEach(instance, instances) {
                        if ((int)cJSON_GetNumberValue(cJSON_GetObjectItem(instance, "LocalPort")) == local_port) {
                            cJSON *ddns_conf = cJSON_GetObjectItem(instance, "DDNS");
                            if (ddns_conf && cJSON_IsTrue(cJSON_GetObjectItem(ddns_conf, "Enable"))) {
                                const char *sub_domain_tpl = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_conf, "SubDomain"));
                                const char *domain = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_conf, "Domain"));
                                if (sub_domain_tpl && domain) {
                                    char port_str[16];
                                    snprintf(port_str, sizeof(port_str), "%d", public_port);
                                    char *sub_domain = str_replace(sub_domain_tpl, "{{.ExternalPort}}", port_str);
                                    char full_domain[256];
                                    snprintf(full_domain, sizeof(full_domain), "%s.%s", sub_domain, domain);
                                    cJSON_AddStringToObject(response_json, "domain", full_domain);
                                    free(sub_domain);
                                }
                            }
                            break; // Found the matching instance, no need to loop further
                        }
                    }

                    char *response_body_str = cJSON_PrintUnformatted(response_json);
                    snprintf(http_response, sizeof(http_response),
                             "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
                             strlen(response_body_str), response_body_str);
                    free(response_body_str);
                    cJSON_Delete(response_json);
                } else if (found == 1) { // Not found
                    strcpy(response_body, "Not Found");
                    snprintf(http_response, sizeof(http_response),
                             "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
                             strlen(response_body), response_body);
                } else { // Error
                    strcpy(response_body, "Internal Server Error");
                    snprintf(http_response, sizeof(http_response),
                             "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
                             strlen(response_body), response_body);
                }
                write(client_sock, http_response, strlen(http_response));
            } else {
                const char *bad_request_body = "Bad Request: Missing or invalid local_port";
                char http_response[256];
                snprintf(http_response, sizeof(http_response),
                         "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
                         strlen(bad_request_body), bad_request_body);
                write(client_sock, http_response, strlen(http_response));
            }
        } else {
            const char *not_found_body = "Not Found";
            char http_response[256];
            snprintf(http_response, sizeof(http_response),
                     "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\n\r\n%s",
                     strlen(not_found_body), not_found_body);
            write(client_sock, http_response, strlen(http_response));
        }
    }

    close(client_sock);
    return NULL;
}

// Starts a non-blocking HTTP server and returns the listening socket fd
int start_http_server(unsigned int port) {
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return -1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        close(server_fd);
        return -1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        return -1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen");
        close(server_fd);
        return -1;
    }

    printf("HTTP API server listening on port %u\n", port);
    return server_fd;
}

void process_ddns(cJSON *ddns_config, const char *secret_id, const char *secret_key) {
    if (!cJSON_IsTrue(cJSON_GetObjectItem(ddns_config, "Enable"))) {
        printf("DDNS module is disabled.\n");
        return;
    }

    const char *domain = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_config, "Domain"));
    const char *sub_domain = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_config, "SubDomain"));
    const char *record_type = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_config, "RecordType"));
    double record_id = cJSON_GetNumberValue(cJSON_GetObjectItem(ddns_config, "RecordId"));
    const char *record_line = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_config, "RecordLine"));
    const char *cache_file = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_config, "CacheFile"));

    if (!secret_id || !secret_key || !domain || !sub_domain || !record_type || !record_line || !cache_file) {
        fprintf(stderr, "DDNS config is missing required fields.\n");
        return;
    }

    char *current_ip = NULL;
    if (strcmp(record_type, "A") == 0) {
        current_ip = get_public_ip4();
        if (!current_ip) {
            fprintf(stderr, "DDNS: Could not get public IPv4.\n");
            return;
        }
        printf("DDNS: Current public IPv4 is %s\n", current_ip);
    } else if (strcmp(record_type, "AAAA") == 0) {
        current_ip = get_public_ip6();
        if (!current_ip) {
            fprintf(stderr, "DDNS: Could not get public IPv6.\n");
            return;
        }
        printf("DDNS: Current public IPv6 is %s\n", current_ip);
    } else {
        fprintf(stderr, "DDNS: Unsupported record type '%s'. Only 'A' and 'AAAA' are supported.\n", record_type);
        return;
    }

    if (!current_ip) {
        fprintf(stderr, "DDNS: Could not get public IP for record type %s.\n", record_type);
        return;
    }

    char *cached_ip = read_ip_cache(cache_file);
    if (cached_ip && strcmp(cached_ip, current_ip) == 0) {
        printf("DDNS: IP has not changed (%s). No update needed.\n", current_ip);
        free(current_ip);
        free(cached_ip);
        return;
    }

    printf("DDNS: IP has changed. Old: %s, New: %s. Updating...\n", cached_ip ? cached_ip : "(none)", current_ip);

    cJSON *body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "Domain", domain);
    cJSON_AddStringToObject(body, "SubDomain", sub_domain);
    cJSON_AddNumberToObject(body, "RecordId", record_id);
    cJSON_AddStringToObject(body, "RecordLine", record_line);
    cJSON_AddStringToObject(body, "Value", current_ip);
    cJSON_AddStringToObject(body, "RecordType", record_type);

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "Updated at %Y-%m-%d %H:%M:%S by zddns", t);
    cJSON_AddStringToObject(body, "Remark", time_str);

    char *body_str = cJSON_PrintUnformatted(body);
    if (do_update_dns(body_str, secret_id, secret_key, NULL, NULL) == 0) {
        printf("DDNS: Update successful. Caching new IP to %s\n", cache_file);
        write_to_file(cache_file, current_ip);
    } else {
        fprintf(stderr, "DDNS: Update failed.\n");
    }

    free(body_str);
    cJSON_Delete(body);
    free(current_ip);
    if (cached_ip) free(cached_ip);
}

void process_natmap(cJSON *natmap_config, const char *secret_id, const char *secret_key, const char *cos_region, const char *cos_bucket) {
    if (!cJSON_IsTrue(cJSON_GetObjectItem(natmap_config, "Enable"))) {
        printf("Natmap module is disabled.\n");
        return;
    }

    const char *instance_path = cJSON_GetStringValue(cJSON_GetObjectItem(natmap_config, "InstancePath"));
    const char *temp_path = cJSON_GetStringValue(cJSON_GetObjectItem(natmap_config, "TempPath"));
    cJSON *instances = cJSON_GetObjectItem(natmap_config, "Instances");
    cJSON *instance = NULL;

    cJSON_ArrayForEach(instance, instances) {
        if (!cJSON_IsTrue(cJSON_GetObjectItem(instance, "Enable"))) {
            printf("Natmap instance is disabled.\n");
            continue;
        }
        const char *protocol = cJSON_GetStringValue(cJSON_GetObjectItem(instance, "Protocol"));
        int local_port = (int)cJSON_GetNumberValue(cJSON_GetObjectItem(instance, "LocalPort"));

        char public_ip[40];
        int public_port;

        printf("Natmap: Searching for mapping for %s/%d...\n", protocol, local_port);
        if (find_natmap_entry(instance_path, protocol, local_port, public_ip, sizeof(public_ip), &public_port) == 0) {
            printf("Natmap: Found mapping: %s:%d\n", public_ip, public_port);

            // --- Caching Logic ---
            char cache_file[256];
            snprintf(cache_file, sizeof(cache_file), "%s/zddns_natmap_%s_%d.cache", temp_path, protocol, local_port);

            char cached_ip_port[64] = {0};
            char current_ip_port[64];
            snprintf(current_ip_port, sizeof(current_ip_port), "%s:%d", public_ip, public_port);

            FILE *cache_f = fopen(cache_file, "r");
            if (cache_f) {
                if (fgets(cached_ip_port, sizeof(cached_ip_port), cache_f)) {
                    // Trim newline
                    cached_ip_port[strcspn(cached_ip_port, "\r\n")] = 0;
                }
                fclose(cache_f);
            }

            if (strcmp(cached_ip_port, current_ip_port) == 0) {
                printf("Natmap: IP and Port for %s/%d have not changed (%s). Skipping update.\n", protocol, local_port, current_ip_port);
                continue; // Skip to the next instance
            }
            printf("Natmap: IP or Port for %s/%d has changed. Old: %s, New: %s. Updating...\n", protocol, local_port, strlen(cached_ip_port) > 0 ? cached_ip_port : "(none)", current_ip_port);
            write_to_file(cache_file, current_ip_port);
            // --- End Caching Logic ---

            cJSON *render_files = cJSON_GetObjectItem(instance, "RenderFiles");
            cJSON *render_file = NULL;
            cJSON_ArrayForEach(render_file, render_files) {
                if (!cJSON_IsTrue(cJSON_GetObjectItem(render_file, "Enable"))) {
                    printf("render_file is disabled.\n");
                    continue;
                }
                // 1. Render template if configured
                const char *template_file = cJSON_GetStringValue(cJSON_GetObjectItem(render_file, "TemplateFile"));
                const char *password = cJSON_GetStringValue(cJSON_GetObjectItem(render_file, "Password"));
                const char *save_path = cJSON_GetStringValue(cJSON_GetObjectItem(render_file, "SavePath"));
                if (template_file && strlen(template_file) > 0 && save_path && strncmp(save_path, "cos://", 6) == 0) {
                    char *rendered_content = render_template(template_file, public_ip, public_port, password);
                    if (rendered_content) {
                        printf("Natmap: Template rendered successfully in memory.\n");
                        // Upload to COS
                        char *cos_path = strdup(save_path + 6); // Skip "cos://"
                        char *object_key = strchr(cos_path, '/');
                        if (object_key) {
                            *object_key = '\0';
                            object_key++;
                            printf("Natmap: Uploading content to COS bucket '%s' as '%s'\n", cos_bucket, object_key);
                            upload_to_cos(secret_id, secret_key, cos_region, cos_bucket, object_key, rendered_content);
                        }
                        free(cos_path);
                        free(rendered_content);
                    }
                }
            }

            // 2. Update DDNS if configured
            cJSON *ddns_conf = cJSON_GetObjectItem(instance, "DDNS");
            if (ddns_conf) {
                if (!cJSON_IsTrue(cJSON_GetObjectItem(ddns_conf, "Enable"))) {
                   continue;
                }
                printf("Natmap: Updating DDNS for %s/%d...\n", protocol, local_port);
                cJSON *body = cJSON_CreateObject();
                cJSON_AddStringToObject(body, "Domain", cJSON_GetStringValue(cJSON_GetObjectItem(ddns_conf, "Domain")));
                const char* sub_domain = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_conf, "SubDomain"));
                char port_str[16];
                snprintf(port_str, sizeof(port_str), "%d", public_port);
                const char* sub_domain_after_port = str_replace(sub_domain, "{{.ExternalPort}}", port_str);
                if (!sub_domain_after_port) {
                    fprintf(stderr, "Failed to replace Port in template\n");
                    sub_domain_after_port = sub_domain; // Fallback to original
                }
                cJSON_AddStringToObject(body, "SubDomain", sub_domain_after_port);
                cJSON_AddNumberToObject(body, "RecordId", cJSON_GetNumberValue(cJSON_GetObjectItem(ddns_conf, "RecordId")));
                cJSON_AddStringToObject(body, "RecordType", cJSON_GetStringValue(cJSON_GetObjectItem(ddns_conf, "RecordType")));
                cJSON_AddStringToObject(body, "RecordLine", cJSON_GetStringValue(cJSON_GetObjectItem(ddns_conf, "RecordLine")));
                cJSON_AddStringToObject(body, "Value", public_ip);

                time_t now = time(NULL);
                struct tm *t = localtime(&now);
                char time_str[64];
                strftime(time_str, sizeof(time_str), "Updated at %Y-%m-%d %H:%M:%S", t);
                cJSON_AddStringToObject(body, "Remark", time_str);
                
                char *body_str = cJSON_PrintUnformatted(body);
                if (do_update_dns(body_str, secret_id, secret_key, NULL, NULL) != 0) {
                    fprintf(stderr, "Natmap: DDNS update for %s failed.\n", sub_domain_after_port);
                }
                free(body_str);
                cJSON_Delete(body);

                // Update cache file after successful updates
            }
        } else {
            fprintf(stderr, "Natmap: No mapping found for %s/%d.\n", protocol, local_port);
        }
    }
}

void *natmap_thread_func(void *arg) {
    task_thread_data_t *data = (task_thread_data_t *)arg;
    if (data->interval == 0) return NULL; // Do not run if interval is 0

    while (1) {
        printf("\n--- Running Natmap Check ---\n");
        process_natmap(data->config, data->secret_id, data->secret_key, data->cos_region, data->cos_bucket);
        sleep(data->interval);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s /path/to/config.json\n", argv[0]);
        return 2;
    }
    const char *config_path = argv[1];
    char *config_str = read_file_content(config_path);
    if (!config_str) {
        fprintf(stderr, "Failed to read config file: %s\n", config_path);
        return 4;
    }

    cJSON *config_json = cJSON_Parse(config_str);
    free(config_str);
    if (!config_json) {
        fprintf(stderr, "Failed to parse config file.\n");
        return 5;
    } 

    cJSON *http_config = cJSON_GetObjectItem(config_json, "HTTP");
    cJSON *tencent_cloud_config = cJSON_GetObjectItem(config_json, "TencentCloud");
    cJSON *ddns_config = cJSON_GetObjectItem(config_json, "DDNS");
    cJSON *natmap_config = cJSON_GetObjectItem(config_json, "Natmap");

    if (!ddns_config || !natmap_config || !http_config || !tencent_cloud_config) {
        fprintf(stderr, "Config file must contain 'HTTP', 'DDNS', 'TencentCloud' and 'Natmap' sections.\n");
        cJSON_Delete(config_json);
        return 6;
    }

    cJSON *cos_config = cJSON_GetObjectItem(tencent_cloud_config, "COS");
    const char *cos_region = cos_config?cJSON_GetStringValue(cJSON_GetObjectItem(cos_config, "Region")):NULL;
    const char *cos_bucket = cos_config?cJSON_GetStringValue(cJSON_GetObjectItem(cos_config, "Bucket")):NULL;

    unsigned int http_listen_port = (unsigned int)cJSON_GetNumberValue(cJSON_GetObjectItem(http_config, "ListenPort"));

    // Get credentials from DDNS section, as they are shared
    const char *secret_id = cJSON_GetStringValue(cJSON_GetObjectItem(tencent_cloud_config, "SecretID"));
    const char *secret_key = cJSON_GetStringValue(cJSON_GetObjectItem(tencent_cloud_config, "SecretKey"));


    unsigned int ddns_interval = (unsigned int)cJSON_GetNumberValue(cJSON_GetObjectItem(ddns_config, "Interval"));
    unsigned int natmap_interval = (unsigned int)cJSON_GetNumberValue(cJSON_GetObjectItem(natmap_config, "Interval"));

    int http_server_fd = -1;
    if (http_config && http_listen_port > 0 && http_listen_port <= 65535) {
        http_server_fd = start_http_server(http_listen_port);
    } else {
        printf("HTTP API module is disabled.\n");
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    // --- Start background tasks in their own threads ---
    pthread_t ddns_tid, natmap_tid;

    // Use malloc for thread data to ensure it persists after main function scope might change
    task_thread_data_t *ddns_task_data = malloc(sizeof(task_thread_data_t));
    *ddns_task_data = (task_thread_data_t){
        .interval = ddns_interval,
        .config = ddns_config,
        .secret_id = secret_id,
        .secret_key = secret_key,
        .cos_region = cos_region,
        .cos_bucket = cos_bucket
    };
    if (cJSON_IsTrue(cJSON_GetObjectItem(ddns_config, "Enable"))) {
        pthread_create(&ddns_tid, NULL, ddns_thread_func, ddns_task_data);
        pthread_detach(ddns_tid);
    }

    task_thread_data_t *natmap_task_data = malloc(sizeof(task_thread_data_t));
    *natmap_task_data = (task_thread_data_t){
        .interval = natmap_interval,
        .config = natmap_config,
        .secret_id = secret_id,
        .secret_key = secret_key,
        .cos_region = cos_region,
        .cos_bucket = cos_bucket
    };
    if (cJSON_IsTrue(cJSON_GetObjectItem(natmap_config, "Enable"))) {
        pthread_create(&natmap_tid, NULL, natmap_thread_func, natmap_task_data);
        pthread_detach(natmap_tid);
    }

    // --- Main thread loop: only handles HTTP server ---
    while (1) {
        // If HTTP server is not running, just sleep to prevent busy-waiting
        if (http_server_fd == -1) {
            sleep(3600); // Sleep for a long time
            continue;
        }

        // The main loop now only cares about accepting new connections.
        // It will block here until a new connection arrives.
        int client_sock = accept(http_server_fd, NULL, NULL);
        if (client_sock >= 0) {
            pthread_t tid;
            http_thread_data_t *thread_data = malloc(sizeof(http_thread_data_t));
            if (thread_data) {
                thread_data->client_sock = client_sock;
                thread_data->natmap_config = natmap_config;
                if (pthread_create(&tid, NULL, http_connection_thread, thread_data) != 0) {
                    perror("pthread_create failed");
                    free(thread_data);
                    close(client_sock);
                }
                pthread_detach(tid); // Detach the thread to auto-reap its resources
            }
        } else {
            // On a blocking socket, accept() failing is usually a real issue.
            perror("accept failed");
            break; // Exit loop on accept error
        }
    }

    if (http_server_fd != -1) {
        close(http_server_fd);
    }
    // In a real-world daemon, you'd signal threads to exit gracefully here.
    // For this app, letting the process exit is sufficient.
    free(ddns_task_data);
    free(natmap_task_data);
    cJSON_Delete(config_json);
    curl_global_cleanup();
    return 0;
}
