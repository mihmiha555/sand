#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/mman.h>

#include "sand.h"

#define DEVICE_FILE_NAME "/dev/sand"
#define MAX_CODE_LEN 4096

int sandbox(int fd, uint8_t code[MAX_CODE_LEN], int size)
{
	int err;

	struct sandbox sandbox = {
		.eax = 0,
		.ebx = 0,
		.ecx = 0,
		.edx = 0,
		.code = code,
		.code_size = (size_t)size
	};

	err = ioctl(fd, SAND_IOCTL_EXECUTE_FUNCTION, &sandbox);
	if (!err) {
		printf("Finished sandbox properly, state:\n");
		printf("\teax = %x\n", sandbox.eax);
		printf("\tebx = %x\n", sandbox.ebx);
		printf("\tecx = %x\n", sandbox.ecx);
		printf("\tedx = %x\n", sandbox.edx);
	}

	return err;
}

int main(int argc, char *argv[])
{
	uint8_t code[MAX_CODE_LEN];
	int fd;
	int arg;

	if (argc == 1) {
		printf("Use: %s < space-separated hex bytes >\n", argv[0]);
		printf("Example: %s 0xCC 0xCD 0x10 0xF4\n", argv[0]);
		return 0;
	}

	for (arg = 1; arg < argc; arg++) {
		unsigned long hex = 0;
		char *endptr;

		hex = strtoul(argv[arg], &endptr, 16);

		if (*endptr != '\0') {
			fprintf(stderr, "Failed to parse code at pos %d.\n", arg - 1);
			return 1;
		}

		if (hex > 0xFFul) {
			fprintf(stderr, "Too large code val at pos %d.\n", arg - 1);
			fprintf(stderr, "Every val must be a byte.\n");
			return 2;
		}

		code[arg - 1] = (uint8_t)hex;
	}

	fd = open(DEVICE_FILE_NAME, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Failed to open file.\n");
		close(fd);
		return 3;
	}

	printf("Will run the following code: ");
	for (arg = 0; arg < argc - 1; arg++) {
		printf("%X ", code[arg]);
	}
	printf("\n");

	if (sandbox(fd, code, argc - 1)) {
		fprintf(stderr, "Failed to run code in sandbox\n");
		close(fd);
		return 4;
	}

	close(fd);
	return 0;
}
