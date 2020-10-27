#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils_cryptor.h"

int main(int argc, char **argv)
{
    char pid[MAX_SIZE_OF_PRODUCT_ID+2] = {0};
    char dev_name[MAX_SIZE_OF_DEVICE_NAME+4] = {0};
    char psk[MAX_SIZE_OF_CRYPT_PSK+8] = {0};
    int i, c;

    const char * program_name = argv[0];
    while ((c = getopt(argc, argv, "p:d:k:")) != EOF)
    switch (c) 
    {
        case 'p':
            strcpy(pid, optarg);
            break;

        case 'd':
            strcpy(dev_name, optarg);
            break;
            
        case 'k':
            strcpy(psk, optarg);
            break;
            
        default:
            fprintf(stderr,
            "usage: %s [options]\n"
            "  [-p <product_id>] \n"
            "  [-d <device_name>] \n"
            "  [-k <device_psk>] \n"
            , program_name);
        return -1;
    }


    printf("Plain text: %s\n", psk);
    int ret = update_devinfo(86013388, pid, dev_name, psk);
    if (ret) {
        printf("encrypt failed\n");
        return -1;
    }

    printf("Encrypted data: %s\n", psk);

    return 0;
    
}

