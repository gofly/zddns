#ifndef TEMPLATE_H
#define TEMPLATE_H

#include <stddef.h>

// Renders a template file by replacing placeholders and saves it to a new file.
// Returns the rendered content as a dynamically allocated string, which the caller must free.
char* render_template(const char* template_path, const char* public_ip, int public_port, const char* password);
char *str_replace(const char *orig, const char *rep, const char *with);

#endif // TEMPLATE_H