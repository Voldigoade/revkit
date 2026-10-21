#include <stdio.h>

static int classify(int value) {
    if (value < 0) {
        return -1;
    }
    if (value == 0) {
        return 0;
    }
    return 1;
}

int main(void) {
    printf("class: %d\n", classify(7));
    return 0;
}
