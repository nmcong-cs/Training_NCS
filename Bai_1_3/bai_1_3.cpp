#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>

struct FILE_HDR {
    char magic[4];
    int version;
    int dataSize;
};

int main() {
    struct FILE_HDR hdr = {
        {'N', 'C', 'S', '1'},
        1,
        100
    };

    FILE* f = fopen("test.bin", "wb"); // ghi ra file test.bin
    if (f == NULL) {
        printf("khong mo duoc file\n");
        return 1;
    }

    fwrite(&hdr, sizeof(hdr), 1, f);
    fclose(f);

    struct FILE_HDR readHdr;

    f = fopen("test.bin", "rb");
    if (f == NULL) {
        printf("khong mo duco file\n");
        return 1;
    }

    fread(&readHdr, sizeof(readHdr), 1, f);
    fclose(f);

    printf("magic: %.4s\n", readHdr.magic);
    printf("version: %d\n", readHdr.version);
    printf("dataSize: %d\n", readHdr.dataSize);

    if (memcmp(readHdr.magic, "NCS1", 4) == 0) {
        printf("magic hop le\n");
    }
    else {
        printf("magic khong hop le\n");
    }

    return 0;
}