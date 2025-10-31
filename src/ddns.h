#ifndef DDNS_H
#define DDNS_H

#include <stddef.h>

// get public IPv6 from an API
char *get_public_ip6();

// get public IPv4 from an API
char *get_public_ip4();

// read IP from cache file
char* read_ip_cache(const char* cache_file);

// perform the DNS update
int do_update_dns(const char *body_json, const char *secretId, const char *secretKey, const char *token, const char *region);

#endif // DDNS_H