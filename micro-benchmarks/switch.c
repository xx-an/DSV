
int foo0(char* argv) {
    return 0;
}

int foo1(char* argv) {
    return 1;
}

int foo2(char* argv) {
    return 2;
}

int foo3(char* argv) {
    return 3;
}

int foo4(char* argv) {
    return 4;
}

int foo5(char* argv) {
    return 5;
}

int main(int argc, char *argv) {
    int a;
    switch (argc) {
        case 5:
        a = foo0(argv);
        break;
        case 6:
        a = foo1(argv);
        break;
        case 7:
        a = foo2(argv);
        break;
        case 10:
        a = foo3(argv);
        break;
        case 11:
        a = foo4(argv);
        break;
    default:
        a = foo5(argv);
        break;
    }
}
