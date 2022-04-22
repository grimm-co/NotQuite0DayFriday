#include "nvram-faker.h"
#include "internal.h"
#include "unistd.h"

EXPORT char * acosNvramConfig_get(const char *key)
{
  char *ret;

  if(!key)
    return NULL;

  ret = nvram_get(key);
  if (!ret)
    ret = "";
  return ret;
}

EXPORT int acosNvramConfig_set(const char * key, const char * value)
{
  if(key == NULL || value == NULL)
    return 0;
  return nvram_set(key, value);
}

EXPORT int acosNvramConfig_invmatch(const char * key, const char *value)
{
  const char *result;

  result = nvram_get(key);
  if (!result)
    return 0;
  return nvram_faker_strcmp(result, value) != 0;
}

EXPORT int acosNvramConfig_match(const char * key, const char *value)
{
  const char *result;

  result = nvram_get(key);
  if (!result)
    return 0;
  return nvram_faker_strcmp(result, value) == 0;
}

//Wait for 5 seconds on startup so we can attach to the upnpd with gdb
//Requires libc. Can be replaced with a large loop if libc cannot be used
static void con() __attribute__((constructor));
void con() {
	sleep(5);
}
