#ifndef NATMAP_H
#define NATMAP_H

#include <stddef.h>

/**
 * @brief Finds a NAT mapping entry in /var/run/natmap.
 *
 * @param protocol The protocol to match (e.g., "tcp").
 * @param inner_port The inner port to match.
 * @param out_ip Buffer to store the found public IP address.
 * @param ip_buf_size Size of the out_ip buffer.
 * @param out_port Pointer to store the found public port.
 * @return 0 on success (entry found), 1 if not found, -1 on error.
 */
int find_natmap_entry(const char *natmap_dir, const char *protocol, int inner_port, char *out_ip, size_t ip_buf_size, int *out_port);

#endif // NATMAP_H