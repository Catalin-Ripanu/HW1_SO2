# HW1_SO2

Just a kernel module called *list.ko* which stores data (strings) in an internal list.
Used the list API [1] implemented in the kernel.

The module exports a directory named *list* to procfs. The directory contains two files:

  1. management: with write-only access; is the interface for transmitting commands to the kernel module

  2. preview: with read-only access; is the interface through which the internal contents of the kernel list can be viewed.

To interact with the kernel list, you must write commands (using the echo command) in the /proc/list/management file:

  1. addf name: adds the name element to the top of the list

  3. adde name: adds the name element to the end of the list

  5. delf name: deletes the first appearance of the name item from the list

  7. dela name: deletes all occurrences of the name element in the list

Viewing the contents of the list is done by viewing the contents of the /proc/list/preview file (use the `cat` command). The format contains one element on each line.


[1]: https://github.com/torvalds/linux/blob/master/include/linux/list.h
