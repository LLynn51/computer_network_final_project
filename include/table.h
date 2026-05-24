#ifndef TABLE_H
#define TABLE_H

#include <stdint.h>

int load_table(const char *filename);
int table_lookup(const char *domain, uint32_t *ip);
void table_free(void);

#endif
