#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
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
	int size;

	if (argc == 1) {
		printf("Usage: %s -f < binary file >\n", argv[0]);
		printf("Example: %s -f code.bin\n", argv[0]);
		printf("Legacy usage: %s < space-separated hex bytes >\n", argv[0]);
		printf("Example: %s 0xCC 0xCD 0x10 0xF4\n", argv[0]);
		return 0;
	}

	if (!strcmp(argv[1], "-f")) {	// New mode
		int fd_in;
		struct stat sb;
		size_t len;
		ssize_t ret, nr = 0;

		if(argc == 2) {
			fprintf(stderr, "Please, specify the binary code file.\n");
			return 5;
		}

		fd_in = open(argv[2], O_RDONLY);
		if (fd_in < 0) {
			fprintf(stderr, "%s: Failed to open binary file.\n", argv[2]);
			return 6;
		}

		if(fstat(fd_in, &sb)) {
			fprintf(stderr, "%s: Failed to get stat of the file.\n", argv[2]);
			close(fd_in);
			return 7;
		}

		len = (size_t)sb.st_size;
		if(!len) {
			fprintf(stderr, "%s: Binary file is empty\n", argv[2]);
			close(fd_in);
			return 8;
		}

		if(len > MAX_CODE_LEN) {
			fprintf(stderr, "%s: Binary file exceeds the allowed size (%d bytes).\n", argv[2], MAX_CODE_LEN);
			close(fd_in);
			return 9;
		}

		size = (int)len;

		while (len != 0 && (ret = read(fd_in, &code[nr], len)) != 0) {
			if (ret == -1) {
				if (errno == EINTR)
					continue;

				fprintf(stderr, "%s: Failed to read code from file.\n", argv[2]);
				close(fd_in);
				return 10;
			}

			len -= ret;
			nr += ret;
		}
		close(fd_in);

	} else {	// Legacy mode

		size = argc - 1;

		if(size > MAX_CODE_LEN) {
			fprintf(stderr, "Code exceeds the allowed size (%d bytes).\n", MAX_CODE_LEN);
			return 9;
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
	}

	fd = open(DEVICE_FILE_NAME, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "%s: Failed to open the device file.\n", DEVICE_FILE_NAME);
		return 3;
	}

	printf("Will run the following code: ");
	for (arg = 0; arg < size; arg++) {
		printf("%X ", code[arg]);
	}
	printf("\n");

	if (sandbox(fd, code, size)) {
		fprintf(stderr, "Failed to run code in sandbox\n");
		close(fd);
		return 4;
	}

	close(fd);
	return 0;
}
