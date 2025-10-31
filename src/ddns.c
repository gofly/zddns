#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cjson/cJSON.h>
#include "ddns.h"

#define ENDPOINT "dnspod.tencentcloudapi.com"
#define SERVICE_FROM_ENDPOINT "dnspod" // derived from endpoint before first dot
#define API_VERSION "2021-03-23" // SDK often uses v20210323, use as X-TC-Version
#define SDK_VERSION "SDK_CPP_3.1.91" // X-TC-RequestClient, can change
#define IP4_API_URL "https://ipv4.ddnspod.com"
#define IP6_API_URL "https://ipv6.ddnspod.com"

// helper to collect response from libcurl
struct mem {
    char *buf;
    size_t len;
};

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct mem *m = (struct mem*)userdata;
    char *tmp = realloc(m->buf, m->len + realsize + 1);
    if (!tmp) return 0;
    m->buf = tmp;
    memcpy(m->buf + m->len, ptr, realsize);
    m->len += realsize;
    m->buf[m->len] = '\0';
    return realsize;
}

// hex encode bytes to lower-case hex string
static char *hex_encode(const unsigned char *in, size_t len) {
    static const char hex[] = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; ++i) {
        out[i*2]   = hex[(in[i] >> 4) & 0xF];
        out[i*2+1] = hex[in[i] & 0xF];
    }
    out[len*2] = '\0';
    return out;
}

// SHA256 digest bytes (binary) of input string
static unsigned char *sha256_bin(const char *data, size_t len) {
    unsigned char *digest = malloc(SHA256_DIGEST_LENGTH);
    if (!digest) return NULL;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, len);
    SHA256_Final(digest, &ctx);
    return digest;
}

// SHA256 hex string
static char *sha256_hex(const char *data, size_t len) {
    unsigned char *bin = sha256_bin(data, len);
    if (!bin) return NULL;
    char *hex = hex_encode(bin, SHA256_DIGEST_LENGTH);
    free(bin);
    return hex;
}

// HMAC-SHA256 binary: key (binary, keylen) and data (string, datalen)
static unsigned char *hmac_sha256_bin(const unsigned char *key, size_t keylen, const char *data, size_t datalen, unsigned int *outlen) {
    unsigned char *result = malloc(EVP_MAX_MD_SIZE);
    if (!result) return NULL;
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx) { free(result); return NULL; }
    if (!HMAC_Init_ex(ctx, key, (int)keylen, EVP_sha256(), NULL)) { HMAC_CTX_free(ctx); free(result); return NULL; }
    if (!HMAC_Update(ctx, (unsigned char*)data, datalen)) { HMAC_CTX_free(ctx); free(result); return NULL; }
    if (!HMAC_Final(ctx, result, outlen)) { HMAC_CTX_free(ctx); free(result); return NULL; }
    HMAC_CTX_free(ctx);
    return result;
}

// build TC3 signature per algorithm:
// kSecret = "TC3" + SecretKey
// kDate = HMAC-SHA256(kSecret, date)
// kService = HMAC-SHA256(kDate, service)
// kSigning = HMAC-SHA256(kService, "tc3_request")
// signature = hex(HMAC-SHA256(kSigning, stringToSign))
static char *tc3_sign(const char *secretKey, const char *date, const char *service, const char *stringToSign) {
    // step keys
    size_t kSecretLen = 3 + strlen(secretKey); // "TC3"+secret
    char *kSecret = malloc(kSecretLen + 1);
    if (!kSecret) return NULL;
    strcpy(kSecret, "TC3");
    strcat(kSecret, secretKey);

    unsigned int olen = 0;
    unsigned char *kDate = hmac_sha256_bin((unsigned char*)kSecret, strlen(kSecret), date, strlen(date), &olen);
    free(kSecret);
    if (!kDate) return NULL;

    unsigned char *kService = hmac_sha256_bin(kDate, olen, service, strlen(service), &olen);
    free(kDate);
    if (!kService) return NULL;

    unsigned char *kSigning = hmac_sha256_bin(kService, olen, "tc3_request", strlen("tc3_request"), &olen);
    free(kService);
    if (!kSigning) return NULL;

    unsigned char *sigbin = hmac_sha256_bin(kSigning, olen, stringToSign, strlen(stringToSign), &olen);
    free(kSigning);
    if (!sigbin) return NULL;

    char *sighex = hex_encode(sigbin, olen);
    free(sigbin);
    return sighex; // caller frees
}

// get current timestamp (seconds since epoch) and date string "YYYY-MM-DD" (UTC)
static void get_timestamp_and_utc_date(long *out_ts, char *out_cred_date, size_t date_buflen) {
    time_t t = time(NULL);
    *out_ts = (long)t;
    struct tm g;
    gmtime_r(&t, &g); // UTC
    // format YYYY-MM-DD
    strftime(out_cred_date, date_buflen, "%Y-%m-%d", &g);
}

// HTTP POST JSON with headers, return response body string (malloced) or NULL
static char *http_post_json_with_headers(const char *url, const char *json_body, struct curl_slist *headers) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct mem m = { .buf = NULL, .len = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(json_body));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) {
        free(m.buf);
        return NULL;
    }
    return m.buf;
}

static char* get_ip_from_url(const char* url) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    struct mem m = { .buf = NULL, .len = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        fprintf(stderr, "Failed to get public IP from %s: %s\n", url, curl_easy_strerror(rc));
        if (m.buf) free(m.buf);
        return NULL;
    }

    if (m.len == 0) {
        fprintf(stderr, "Failed to get public IP from %s: empty response\n", url);
        if (m.buf) free(m.buf);
        return NULL;
    }
    
    // The response is just the IP, so we can use it directly.
    // Trim trailing newline if it exists
    if (m.buf[m.len - 1] == '\n') {
        m.buf[m.len - 1] = '\0';
    }

    return m.buf;
}

char *get_public_ip6() {
    return get_ip_from_url(IP6_API_URL);
}

char *get_public_ip4() {
    return get_ip_from_url(IP4_API_URL);
}

char* read_ip_cache(const char* cache_file) {
    FILE *f = fopen(cache_file, "r");
    if (!f) return NULL;
    char *ip = malloc(40); // Enough for an IPv6
    if (!ip) { fclose(f); return NULL; }
    if (fgets(ip, 40, f) == NULL) {
        free(ip);
        fclose(f);
        return NULL;
    }
    fclose(f);
    ip[strcspn(ip, "\r\n")] = 0; // Remove trailing newline
    return ip;
}

int do_update_dns(const char *body_json, const char *secretId, const char *secretKey, const char *token, const char *region) {
    printf("Performing DDNS update with body: %s\n", body_json);
    // Prepare timestamp and credential scope
    long ts = 0;
    char credDate[64] = {0};
    get_timestamp_and_utc_date(&ts, credDate, sizeof(credDate)); // credDate = YYYY-MM-DD

    // payload hash
    char *payloadHash = sha256_hex(body_json, strlen(body_json));
    if (!payloadHash) {
        fprintf(stderr, "Failed to compute payload SHA256\n");
        return 1;
    }

    // canonical request
    // method = POST
    // canonicalUri = "/"
    // canonicalQueryString = ""
    // canonicalHeaders = "content-type:application/json\nhost:dnspod.tencentcloudapi.com\n"
    // signedHeaders = "content-type;host"
    char canonicalHeaders[512];
    snprintf(canonicalHeaders, sizeof(canonicalHeaders),
             "content-type:application/json\nhost:%s\n", ENDPOINT);
    const char *signedHeaders = "content-type;host";

    size_t canonicalRequestLen = strlen("POST\n/\n\n\n\n") + strlen(canonicalHeaders) + strlen(signedHeaders) + strlen(payloadHash) + 64;
    char *canonicalRequest = malloc(canonicalRequestLen);
    if (!canonicalRequest) { free(payloadHash); return 1; }
    snprintf(canonicalRequest, canonicalRequestLen, "POST\n/\n\n%s\n%s\n%s", canonicalHeaders, signedHeaders, payloadHash);

    // stringToSign
    const char *algorithm = "TC3-HMAC-SHA256";
    char credentialScope[256];
    snprintf(credentialScope, sizeof(credentialScope), "%s/%s/tc3_request", credDate, SERVICE_FROM_ENDPOINT);

    char *canonicalRequestHash = sha256_hex(canonicalRequest, strlen(canonicalRequest));
    if (!canonicalRequestHash) { free(payloadHash); free(canonicalRequest); return 1; }

    size_t stringToSignLen = strlen(algorithm) + 1 + 32 + 1 + strlen(credentialScope) + 1 + strlen(canonicalRequestHash) + 16;
    char *stringToSign = malloc(stringToSignLen);
    if (!stringToSign) { free(payloadHash); free(canonicalRequest); free(canonicalRequestHash); return 1; }
    snprintf(stringToSign, stringToSignLen, "%s\n%ld\n%s\n%s", algorithm, ts, credentialScope, canonicalRequestHash);

    // signature
    char *signature = tc3_sign(secretKey, credDate, SERVICE_FROM_ENDPOINT, stringToSign);
    if (!signature) {
        fprintf(stderr, "Failed to compute signature\n");
        free(payloadHash); free(canonicalRequest); free(canonicalRequestHash); free(stringToSign);
        return 1;
    }

    // Authorization header:
    // "TC3-HMAC-SHA256 Credential=SecretId/credentialScope, SignedHeaders=content-type;host, Signature=signature"
    char authorization[2048];
    snprintf(authorization, sizeof(authorization),
             "TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
             secretId, credentialScope, signedHeaders, signature);

    // Build headers
    struct curl_slist *headers = NULL;
    char hosthdr[256];
    snprintf(hosthdr, sizeof(hosthdr), "Host: %s", ENDPOINT);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, hosthdr);

    char actionhdr[256];
    snprintf(actionhdr, sizeof(actionhdr), "X-TC-Action: ModifyRecord");
    headers = curl_slist_append(headers, actionhdr);

    char versionhdr[256];
    snprintf(versionhdr, sizeof(versionhdr), "X-TC-Version: %s", API_VERSION);
    headers = curl_slist_append(headers, versionhdr);

    if (region && strlen(region) > 0) {
        char tmph[256];
        snprintf(tmph, sizeof(tmph), "X-TC-Region: %s", region);
        headers = curl_slist_append(headers, tmph);
    }
    if (token && strlen(token) > 0) {
        char tmph[512];
        snprintf(tmph, sizeof(tmph), "X-TC-Token: %s", token);
        headers = curl_slist_append(headers, tmph);
    }

    char ts_hdr[128];
    snprintf(ts_hdr, sizeof(ts_hdr), "X-TC-Timestamp: %ld", ts);
    headers = curl_slist_append(headers, ts_hdr);

    char authhdr[2300];
    snprintf(authhdr, sizeof(authhdr), "Authorization: %s", authorization);
    headers = curl_slist_append(headers, authhdr);

    char reqclient[256];
    snprintf(reqclient, sizeof(reqclient), "X-TC-RequestClient: %s", SDK_VERSION);
    headers = curl_slist_append(headers, reqclient);

    // Connection header - emulate m_clientProfile.IsKeepAlive() true
    headers = curl_slist_append(headers, "Connection: Keep-Alive");

    // Compose URL
    char url[512];
    snprintf(url, sizeof(url), "https://%s/", ENDPOINT);

    // send HTTP request
    char *resp = http_post_json_with_headers(url, body_json, headers);

    int ret_code = 0;
    if (!resp) {
        fprintf(stderr, "HTTP request failed or empty response\n");
        ret_code = 1;
    } else {
        printf("HTTP response:\n%s\n", resp);

        // Check for error in response
        cJSON *resp_json = cJSON_Parse(resp);
        if (resp_json) {
            cJSON *response_obj = cJSON_GetObjectItem(resp_json, "Response");
            if (response_obj) {
                cJSON *error_obj = cJSON_GetObjectItem(response_obj, "Error");
                if (error_obj) {
                    fprintf(stderr, "API returned an error.\n");
                    ret_code = 1;
                }
            }
            cJSON_Delete(resp_json);
        }
    }

    // cleanup
    curl_slist_free_all(headers);
    free(payloadHash);
    free(canonicalRequest);
    free(canonicalRequestHash);
    free(stringToSign);
    free(signature);
    free(resp);

    return ret_code;
}