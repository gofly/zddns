#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for sleep()
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include "ddns.h"
#include "natmap.h"
#include "cos.h"
#include "template.h"

// Compile: gcc -o zddns main.c ddns.c natmap.c cos.c template.c -I./cJSON -L./cJSON -lcjson -lcurl -lssl -lcrypto -lm
// Usage:
//   # run:
//   ./zddns /path/to/config.json

void process_ddns(cJSON *ddns_config);
void process_natmap(cJSON *natmap_config, const char *secret_id, const char *secret_key);

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

void process_ddns(cJSON *ddns_config) {
    if (!cJSON_IsTrue(cJSON_GetObjectItem(ddns_config, "Enable"))) {
        printf("DDNS module is disabled.\n");
        return;
    }

    const char *secret_id = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_config, "SecretID"));
    const char *secret_key = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_config, "SecretKey"));
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

void process_natmap(cJSON *natmap_config, const char *secret_id, const char *secret_key) {
    if (!cJSON_IsTrue(cJSON_GetObjectItem(natmap_config, "Enable"))) {
        printf("Natmap module is disabled.\n");
        return;
    }

    cJSON *cos_config = cJSON_GetObjectItem(natmap_config, "COS");
    const char *cos_region = cJSON_GetStringValue(cJSON_GetObjectItem(cos_config, "Region"));
    const char *cos_bucket = cJSON_GetStringValue(cJSON_GetObjectItem(cos_config, "Bucket"));
    
    const char *instance_path = cJSON_GetStringValue(cJSON_GetObjectItem(natmap_config, "InstancePath"));
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
            snprintf(cache_file, sizeof(cache_file), "/tmp/zddns_natmap_%s_%d.cache", protocol, local_port);

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

            // 1. Render template if configured
            const char *template_file = cJSON_GetStringValue(cJSON_GetObjectItem(instance, "TemplateFile"));
            const char *password = cJSON_GetStringValue(cJSON_GetObjectItem(instance, "Password"));
            const char *save_path = cJSON_GetStringValue(cJSON_GetObjectItem(instance, "SavePath"));
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

            // 2. Update DDNS if configured
            cJSON *ddns_conf = cJSON_GetObjectItem(instance, "DDNS");
            if (ddns_conf) {
                if (!cJSON_IsTrue(cJSON_GetObjectItem(ddns_conf, "Enable"))) {
                   continue;
                }
                printf("Natmap: Updating DDNS for %s/%d...\n", protocol, local_port);
                cJSON *body = cJSON_CreateObject();
                cJSON_AddStringToObject(body, "Domain", cJSON_GetStringValue(cJSON_GetObjectItem(ddns_conf, "Domain")));
                cJSON_AddStringToObject(body, "SubDomain", cJSON_GetStringValue(cJSON_GetObjectItem(ddns_conf, "SubDomain")));
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
                    fprintf(stderr, "Natmap: DDNS update for %s failed.\n", cJSON_GetStringValue(cJSON_GetObjectItem(ddns_conf, "SubDomain")));
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

    cJSON *ddns_config = cJSON_GetObjectItem(config_json, "DDNS");
    cJSON *natmap_config = cJSON_GetObjectItem(config_json, "Natmap");

    if (!ddns_config || !natmap_config) {
        fprintf(stderr, "Config file must contain 'DDNS' and 'Natmap' sections.\n");
        cJSON_Delete(config_json);
        return 6;
    }

    // Get credentials from DDNS section, as they are shared
    const char *secret_id = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_config, "SecretID"));
    const char *secret_key = cJSON_GetStringValue(cJSON_GetObjectItem(ddns_config, "SecretKey"));

    unsigned int ddns_interval = (unsigned int)cJSON_GetNumberValue(cJSON_GetObjectItem(ddns_config, "Interval"));
    unsigned int natmap_interval = (unsigned int)cJSON_GetNumberValue(cJSON_GetObjectItem(natmap_config, "Interval"));

    curl_global_init(CURL_GLOBAL_DEFAULT);

    time_t last_ddns_check = 0;
    time_t last_natmap_check = 0;

    while (1) {
        time_t now = time(NULL);
        if (now - last_ddns_check >= ddns_interval) {
            printf("\n--- Running DDNS Check ---\n");
            process_ddns(ddns_config);
            last_ddns_check = now;
        }
        if (now - last_natmap_check >= natmap_interval) {
            printf("\n--- Running Natmap Check ---\n");
            process_natmap(natmap_config, secret_id, secret_key);
            last_natmap_check = now;
        }
        sleep(10);
    }

    cJSON_Delete(config_json);
    curl_global_cleanup();
    return 0;
}
