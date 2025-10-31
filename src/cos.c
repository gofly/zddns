#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "cos.h"

#define MAX_URL 512
#define MAX_AUTH 1024

// Helper to convert binary data to a lowercase hex string
static void to_hex(const unsigned char *in, size_t len, char *out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = hex_chars[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[in[i] & 0x0F];
    }
    out[len * 2] = '\0';
}

// Helper for HMAC-SHA1
static void hmac_sha1(const char *key, const char *msg, unsigned char *out) {
    unsigned int len = SHA_DIGEST_LENGTH;
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, strlen(key), EVP_sha1(), NULL);
    HMAC_Update(ctx, (const unsigned char *)msg, strlen(msg));
    HMAC_Final(ctx, out, &len);
    HMAC_CTX_free(ctx);
}

// Helper for SHA1
static void sha1_hex(const char *data, size_t len, char *out) {
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)data, len, digest);
    to_hex(digest, SHA_DIGEST_LENGTH, out);
}


struct upload_data {
    const char *ptr;
    size_t len;
};

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    struct upload_data *upload_ctx = (struct upload_data *)userdata;
    size_t to_copy = (upload_ctx->len < size * nmemb) ? upload_ctx->len : size * nmemb;
    memcpy(ptr, upload_ctx->ptr, to_copy);
    upload_ctx->ptr += to_copy;
    upload_ctx->len -= to_copy;
    return to_copy;
}

// URL-encodes a string. The caller must free the returned string.
static char* url_encode(CURL *curl, const char *str) {
    if (!str) return NULL;
    char *encoded = curl_easy_escape(curl, str, 0);
    if (!encoded) {
        fprintf(stderr, "curl_easy_escape failed\n");
        return NULL;
    }
    // The curl_easy_escape function returns a malloc'd string
    // We will strdup it so the caller can free it with a standard free()
    char *result = strdup(encoded);
    curl_free(encoded);
    return result;
}

int upload_to_cos(const char *secret_id, const char *secret_key, 
                  const char *region, const char *bucket,
                  const char *object_key, const char *file_content) {
    char url[MAX_URL];
    snprintf(url, sizeof(url),
             "https://%s.cos.%s.myqcloud.com/%s", bucket, region, object_key);

    // === 生成签名 ===
    time_t now = time(NULL);
    long start_time = now - 60;
    long end_time = now + 3600;
    char key_time[64];
    snprintf(key_time, sizeof(key_time), "%ld;%ld", start_time, end_time);

    unsigned char sign_key_bin[SHA_DIGEST_LENGTH];
    char sign_key_hex[SHA_DIGEST_LENGTH * 2 + 1];
    hmac_sha1(secret_key, key_time, sign_key_bin);
    to_hex(sign_key_bin, SHA_DIGEST_LENGTH, sign_key_hex);

    // Calculate SHA1 hash of the file content
    char content_sha1_hex[SHA_DIGEST_LENGTH * 2 + 1];
    sha1_hex(file_content, strlen(file_content), content_sha1_hex);

    // For URL encoding, we need a curl handle
    CURL *temp_curl_for_encode = curl_easy_init();
    if (!temp_curl_for_encode) {
        return -1;
    }

    char host_str[256];
    snprintf(host_str, sizeof(host_str), "%s.cos.%s.myqcloud.com", bucket, region);
    char *encoded_host = url_encode(temp_curl_for_encode, host_str);
    char *encoded_content_type = url_encode(temp_curl_for_encode, "text/plain");

    curl_easy_cleanup(temp_curl_for_encode);

    // 计算 stringToSign
    char http_string[1024];
    snprintf(http_string, sizeof(http_string),
             "put\n/%s\n\ncontent-length=%zu&content-type=%s&host=%s\n",
             object_key, strlen(file_content), encoded_content_type, encoded_host);
    free(encoded_host);
    free(encoded_content_type);
    
    // Hash the HttpString
    char http_string_digest[SHA_DIGEST_LENGTH * 2 + 1];
    sha1_hex(http_string, strlen(http_string), http_string_digest);

    // Construct the StringToSign
    char string_to_sign[1024];
    snprintf(string_to_sign, sizeof(string_to_sign), "sha1\n%s\n%s\n", key_time, http_string_digest);

    // Signature is hmac_sha1(SignKey, StringToSign)
    unsigned char signature_bin[SHA_DIGEST_LENGTH];
    char signature_hex[SHA_DIGEST_LENGTH * 2 + 1];
    hmac_sha1(sign_key_hex, string_to_sign, signature_bin);
    to_hex(signature_bin, SHA_DIGEST_LENGTH, signature_hex);

    // 生成 Authorization 头
    char auth[MAX_AUTH];
    snprintf(auth, sizeof(auth),
             "q-sign-algorithm=sha1&q-ak=%s&q-sign-time=%s&q-key-time=%s&q-header-list=content-length;content-type;host&q-url-param-list=&q-signature=%s",
             secret_id, key_time, key_time, signature_hex);

    char auth_header[MAX_AUTH + 32];
    snprintf(auth_header, sizeof(auth_header), "Authorization: %s", auth);

    char host_header[256];
    snprintf(host_header, sizeof(host_header), "Host: %s.cos.%s.myqcloud.com", bucket, region);

    // === CURL 上传 ===
    CURL *curl = curl_easy_init();
    if (!curl) {
        return -1;
    }

    struct upload_data upload_ctx;
    upload_ctx.ptr = file_content;
    upload_ctx.len = strlen(file_content);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, host_header);
    
    char content_type_header[] = "Content-Type: text/plain";
    char content_length_header[64];
    snprintf(content_length_header, sizeof(content_length_header), "Content-Length: %zu", upload_ctx.len);
    headers = curl_slist_append(headers, content_type_header);
    headers = curl_slist_append(headers, content_length_header);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)upload_ctx.len);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Upload failed: %s\n", curl_easy_strerror(res));
    } else {
        printf("✅ Upload success: %s\n", url);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK) ? 0 : -1;
}