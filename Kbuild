# Kbuild file for Sand kernel module

# If the module is built out-of-tree, CONFIG_SAND is not set
# so we set it to "m" (module)
CONFIG_SAND ?= m

sand-objs		= sand_low.o sand_high.o
obj-$(CONFIG_SAND)	+= sand.o
