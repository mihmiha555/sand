#ifndef __SAND_H__
#define __SAND_H__

#define SAND_IOCTL_EXECUTE_FUNCTION \
	_IOWR(100, 0, struct sandbox)

struct sandbox {
	unsigned int	eax;
	unsigned int	ebx;
	unsigned int	ecx;
	unsigned int	edx;

	void  *code;
	size_t code_size;
};

#endif
