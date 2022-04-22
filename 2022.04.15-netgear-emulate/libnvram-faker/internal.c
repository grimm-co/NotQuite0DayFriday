#include <string.h>

int nvram_faker_strcmp(const char * s1, const char * s2)
{
  for (int i = 0; ; i++)
  {
    if (s1[i] != s2[i])
      return s1[i] < s2[i] ? -1 : 1;

    if (s1[i] == '\0')
      return 0;
  }
}

int nvram_faker_strlen(const char * value)
{
  int i;
  for(i = 0; *value != 0; i++, value++);
  return i;
}

