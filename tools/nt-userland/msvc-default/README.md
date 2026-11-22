# MSVC default-linker compatibility fixture

This directory deliberately uses the normal MSVC console toolchain defaults.
It is a regression input for the PE loader, not part of the freestanding demo.

From an x64 Native Tools Command Prompt for Visual Studio:

```bat
build.cmd
```

The command invokes `cl.exe` with no custom compiler or linker switches. The
result is `build\\hello.exe`; inspect it with `dumpbin /headers` and
`dumpbin /imports`.

Expected source program:

```c
#include <stdio.h>

int main(void)
{
    puts("Hello, world!");
    return 0;
}
```

**Current loader progress:** PE section data is now copied into anonymous
image pages, so the loader no longer requires `FileAlignment == 4096` or
page-aligned raw file offsets/sizes. It now applies DIR64 base relocations if the preferred image address is
occupied, accepts high-entropy-VA flags, and maps a structurally aligned
exception directory. It still rejects imports, TLS, CFG/load-config data, and
CLR images; unwind dispatch is not implemented. The ordinary MSVC executable is therefore still not expected to run;
this fixture remains a regression input. The old freestanding fixture is
unchanged.
