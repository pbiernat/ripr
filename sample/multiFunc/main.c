#include <stdio.h>
#include <stdlib.h>


int func_3(int a, int b) {
    puts("Inside func_3\n");
    return (a * b);
}

int func_2(int a, int b) {
    puts("Inside func_2\n");
    return (a + b);

}


int func_1() {
    puts("Inside func_1\n");

    return (func_2(1,2) + func_3(3,4));

}

int main(int argc, char ** argv) {
    int a;

    a = func_1();
    printf("Answer: %d\n", a);
    return 0;
}
