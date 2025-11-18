#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "template.h"

// Helper to read file content
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

// Simple string replacement function
char *str_replace(const char *orig, const char *rep, const char *with) {
    char *result;
    const char *ins;
    char *tmp;
    int len_rep;
    int len_with;
    int len_front;
    int count;

    if (!orig || !rep) return NULL;
    len_rep = strlen(rep);
    if (len_rep == 0) return NULL;
    if (!with) with = "";
    len_with = strlen(with);

    ins = orig;
    for (count = 0; (tmp = strstr(ins, rep)); ++count) {
        ins = tmp + len_rep;
    }

    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);
    if (!result) return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep;
    }
    strcpy(tmp, orig);
    return result;
}

char* render_template(const char* template_path, const char* public_ip, int public_port, const char* password) {
    char *template_content = read_file_content(template_path);
    if (!template_content) {
        fprintf(stderr, "Failed to read template file: %s\n", template_path);
        return NULL;
    }

     time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);

    char *content_after_time = str_replace(template_content, "{{.Time}}", time_str);
    free(template_content);
    if (!content_after_time) {
        fprintf(stderr, "Failed to replace Time in template\n");
        return NULL;
    }
    
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", public_port);

    char *content_after_ip = str_replace(content_after_time, "{{.ExternalIP}}", public_ip);
    free(content_after_time);
    if (!content_after_ip) {
        fprintf(stderr, "Failed to replace IP in template\n");
        return NULL;
    }

    char *content_after_port = str_replace(content_after_ip, "{{.ExternalPort}}", port_str);
    free(content_after_ip);
    if (!content_after_port) {
        fprintf(stderr, "Failed to replace Port in template\n");
        return NULL;
    }

    char *rendered_content_final = str_replace(content_after_port, "{{.Password}}", password);
    free(content_after_port);
    if (!rendered_content_final) {
        fprintf(stderr, "Failed to replace Password in template\n");
        return NULL;
    }

    return rendered_content_final;
}