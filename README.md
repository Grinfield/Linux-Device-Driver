# Linux-Device-Driver

Examples of Linux Device Drivers, currently for my own machine with kernel 3.10(Centos 7.9.2009).

**NOTE**: This is a GPL licensed fork of the original [Linux-Device-Driver](https://github.com/d0u9/Linux-Device-Driver.git).
It's just for the aim of learning. For for information, please visit the original work.

# Before start

The examples in this repo are compiled against Linux Kernel 5.10. Other versions
of the Kernel are not tested.

Set `KERNELDIR` environment variable to the Linux kernel source dir, and export 
it to your local shell.

```bash
export KERNELDIR=/path/to/kernel/source/
```

This environment variable is mainly used in Makefile to determine which kernel
source tree the drivers are built against.

---

# License

Linux-Device-Driver by d0u9 is licensed under a
[GNU General Public License, version 2][1].

---

### ¶ The end


[1]: https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
