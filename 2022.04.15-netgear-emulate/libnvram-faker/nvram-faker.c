#include "nvram-faker.h"
#include "internal.h"
#if PRINT_REQUESTS
#include "stdlib.h"
#include "unistd.h"
#endif

#include "entries.h"

EXPORT char *nvram_get(const char *key)
{
    int index = 0;
    const char * key_pos;
    const char * pos = entries[0].key;

#if PRINT_REQUESTS
    write(2, "Getting ", 8);
    write(2, key, nvram_faker_strlen(key));
    write(2, "\r\n", 2);
#endif

    while(pos) {
      key_pos = key;
      while(*key_pos == *pos && *key_pos != 0 && *pos != 0) {
        key_pos++;
        pos++;
      }
      if(*key_pos == *pos && *key_pos == 0)
        return entries[index].value;

      index++;
      pos = entries[index].key;
    }

    return NULL;
}

EXPORT int nvram_set(const char *key, const char*value)
{
#if PRINT_REQUESTS
    write(2, "Setting ", 8);
    write(2, key, nvram_faker_strlen(key));
    write(2, " = ", 3);
    write(2, value, nvram_faker_strlen(value));
    write(2, "\r\n", 2);
#endif
	//TODO implement setting
	return 0;
}

