#ifndef COS_H
#define COS_H

int upload_to_cos(const char *secret_id, const char *secret_key,
                  const char *region, const char *bucket,
                  const char *object_key, const char *file_content);

#endif // COS_H