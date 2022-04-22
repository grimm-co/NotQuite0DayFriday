#ifndef __NVRAM_FAKER_H__
#define __NVRAM_FAKER_H__

#define EXPORT __attribute__((visibility("default")))

//If you want to print requests (require libc to already be loaded)
#define PRINT_REQUESTS 1

//The main function we're faking
char *nvram_get(const char *key);

int nvram_set(const char *key, const char*value);

//The entry interface
struct entry {
  char * key;
  char * value;
};

#endif /* __NVRAM_FAKER_H__ */
