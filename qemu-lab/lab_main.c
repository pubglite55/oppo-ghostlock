#include <unistd.h>
#include <stdio.h>
int main(void) {
  fprintf(stderr, "[lab] entered main (constructor already ran)\n");
  for (int i = 0; i < 600; i++) sleep(1);
  return 0;
}
