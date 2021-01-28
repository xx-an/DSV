#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int foo() {
  printf("Hello! we are in foo\n");
}

int bar() {
  printf("Hello! we are in bar\n");
}

int baz() {
  printf("Hello! we are in baz\n");
}

int main(int argc, const char* argv[])
{
  int a;
  srand(time(NULL));
  while(1) {
    a = rand() % 3;
    if(a == 0) foo();
    else if(a == 1) bar();
    else baz();
  }
  return 0;
}

