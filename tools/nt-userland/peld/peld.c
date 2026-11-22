#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <wchar.h>
#include <ctype.h>
#include <malloc.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <stdarg.h>

#define W __attribute__((ms_abi))
#define ARCH_SET_GS 0x1001

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t i32;
typedef int64_t i64;
typedef void *HANDLE;
typedef u32 DWORD;
typedef int BOOL;
typedef u16 WCHAR;

extern char **environ;

struct dd { u32 rva, size; };

struct pe_opt {
	u16 magic;
	u8 maj, min;
	u32 size_code, size_idata, size_udata, entry, base_code;
	u64 image_base;
	u32 sec_align, file_align;
	u16 os_maj, os_min, img_maj, img_min, sub_maj, sub_min;
	u32 win32ver, size_image, size_headers, checksum;
	u16 subsystem, dll_chars;
	u64 stack_res, stack_commit, heap_res, heap_commit;
	u32 loader_flags, nrva;
	struct dd dir[16];
};

struct pe_file { u16 machine, nsec; u32 ts, symptr, nsym; u16 optsize, chars; };

struct pe_sec {
	char name[8];
	u32 vsize, va, rawsize, rawptr, relptr, lnptr;
	u16 nrel, nln;
	u32 chars;
};

struct imp_desc { u32 oft, ts, fwd, name, ft; };
struct tls_dir { u64 start, end, index, callbacks; u32 zero, chars; };

static u8 *g_base;
static u64 g_image_size;
static char g_path[4096];
static char *g_cmdline_a;
static WCHAR *g_cmdline_w;
static u8 *g_teb;
static u8 *g_peb;
static u32 g_last_error;

static void fatal(const char *fmt, const char *a)
{
	fprintf(stderr, "peld: ");
	fprintf(stderr, fmt, a);
	fputc('\n', stderr);
	_exit(127);
}

W static void unimpl(const char *name)
{
	fprintf(stderr, "peld: unimplemented import %s\n", name);
	_exit(127);
}

static void *make_thunk(const char *name)
{
	static u8 *pool;
	static size_t used;
	u8 *p;
	u64 a = (u64)name, f = (u64)unimpl;

	if (!pool || used + 32 > 65536) {
		pool = mmap(NULL, 65536, PROT_READ | PROT_WRITE | PROT_EXEC,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (pool == MAP_FAILED)
			fatal("cannot allocate thunk pool%s", "");
		used = 0;
	}
	p = pool + used;
	used += 32;
	p[0] = 0x48; p[1] = 0xB9; memcpy(p + 2, &a, 8);
	p[10] = 0x48; p[11] = 0xB8; memcpy(p + 12, &f, 8);
	p[20] = 0xFF; p[21] = 0xE0;
	return p;
}

static size_t u16len(const WCHAR *s)
{
	size_t n = 0;
	while (s[n])
		n++;
	return n;
}

static size_t utf8_to_utf16(const u8 *s, size_t n, WCHAR *d, size_t cap)
{
	size_t i = 0, o = 0;

	while (i < n) {
		u32 c = s[i++];

		if (c >= 0xF0 && i + 3 <= n) {
			c = ((c & 7) << 18) | ((s[i] & 63) << 12) |
			    ((s[i + 1] & 63) << 6) | (s[i + 2] & 63);
			i += 3;
		} else if (c >= 0xE0 && i + 2 <= n) {
			c = ((c & 15) << 12) | ((s[i] & 63) << 6) | (s[i + 1] & 63);
			i += 2;
		} else if (c >= 0xC0 && i + 1 <= n) {
			c = ((c & 31) << 6) | (s[i] & 63);
			i += 1;
		}
		if (c >= 0x10000) {
			c -= 0x10000;
			if (d && o + 1 < cap) {
				d[o] = 0xD800 | (c >> 10);
				d[o + 1] = 0xDC00 | (c & 0x3FF);
			}
			o += 2;
		} else {
			if (d && o < cap)
				d[o] = c;
			o++;
		}
	}
	return o;
}

static size_t utf16_to_utf8(const WCHAR *s, size_t n, u8 *d, size_t cap)
{
	size_t i = 0, o = 0;

	while (i < n) {
		u32 c = s[i++];
		u8 t[4];
		size_t k;

		if (c >= 0xD800 && c < 0xDC00 && i < n) {
			c = 0x10000 + ((c - 0xD800) << 10) + (s[i++] - 0xDC00);
		}
		if (c < 0x80) {
			t[0] = c; k = 1;
		} else if (c < 0x800) {
			t[0] = 0xC0 | (c >> 6); t[1] = 0x80 | (c & 63); k = 2;
		} else if (c < 0x10000) {
			t[0] = 0xE0 | (c >> 12); t[1] = 0x80 | ((c >> 6) & 63);
			t[2] = 0x80 | (c & 63); k = 3;
		} else {
			t[0] = 0xF0 | (c >> 18); t[1] = 0x80 | ((c >> 12) & 63);
			t[2] = 0x80 | ((c >> 6) & 63); t[3] = 0x80 | (c & 63); k = 4;
		}
		if (d && o + k <= cap)
			memcpy(d + o, t, k);
		o += k;
	}
	return o;
}

static char *wide_dup(const WCHAR *w)
{
	size_t n = u16len(w);
	size_t m = utf16_to_utf8(w, n, NULL, 0);
	char *r = malloc(m + 1);

	utf16_to_utf8(w, n, (u8 *)r, m);
	r[m] = 0;
	return r;
}

static int h2fd(HANDLE h)
{
	u64 v = (u64)h;

	if (v == (u64)-1 || v < 4)
		return -1;
	return (int)(v / 4 - 1);
}

static HANDLE fd2h(int fd)
{
	return (HANDLE)(u64)((u64)(fd + 1) * 4);
}

static void set_err(u32 e)
{
	g_last_error = e;
	if (g_teb)
		*(u32 *)(g_teb + 0x68) = e;
}

static u32 errno_to_win(int e)
{
	switch (e) {
	case ENOENT: return 2;
	case EACCES: return 5;
	case EEXIST: return 80;
	case EBADF: return 6;
	case EINVAL: return 87;
	case ENOMEM: return 8;
	default: return 31;
	}
}

W static void ExitProcess(u32 code)
{
	fflush(NULL);
	_exit(code & 0xff);
}

W static BOOL TerminateProcess(HANDLE h, u32 code)
{
	(void)h;
	fflush(NULL);
	_exit(code & 0xff);
}

W static HANDLE GetCurrentProcess(void) { return (HANDLE)(i64)-1; }
W static HANDLE GetCurrentThread(void) { return (HANDLE)(i64)-2; }
W static u32 GetCurrentProcessId(void) { return getpid(); }
W static u32 GetCurrentThreadId(void) { return syscall(SYS_gettid); }
W static u32 GetLastError(void) { return g_last_error; }
W static void SetLastError(u32 e) { set_err(e); }
W static u32 GetVersion(void) { return 0x0A | (19045u << 16); }
W static BOOL IsDebuggerPresent(void) { return 0; }
W static void *EncodePointer(void *p) { return p; }
W static void *DecodePointer(void *p) { return p; }
W static void *SetUnhandledExceptionFilter(void *f) { (void)f; return NULL; }
W static i32 UnhandledExceptionFilter(void *p) { (void)p; return 0; }
W static BOOL SetConsoleCtrlHandler(void *f, BOOL a) { (void)f; (void)a; return 1; }
W static u32 SetHandleCount(u32 n) { return n; }
W static BOOL HeapSetInformation(HANDLE h, i32 c, void *p, size_t n)
{
	(void)h; (void)c; (void)p; (void)n;
	return 1;
}

W static BOOL IsProcessorFeaturePresent(u32 f)
{
	switch (f) {
	case 6: case 10: case 13:
		return 1;
	default:
		return 0;
	}
}

W static void Sleep(u32 ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	nanosleep(&ts, NULL);
}

W static void GetSystemTimeAsFileTime(u64 *ft)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	*ft = ((u64)ts.tv_sec + 11644473600ULL) * 10000000ULL + ts.tv_nsec / 100;
}

W static BOOL QueryPerformanceCounter(i64 *c)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	*c = (i64)ts.tv_sec * 10000000LL + ts.tv_nsec / 100;
	return 1;
}

W static BOOL QueryPerformanceFrequency(i64 *f)
{
	*f = 10000000;
	return 1;
}

W static u32 GetTickCount(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (u32)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

W static u64 GetTickCount64(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (u64)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

#define HEAP_ZERO 8
static u8 g_heap_tag;

W static HANDLE GetProcessHeap(void) { return &g_heap_tag; }
W static HANDLE HeapCreate(u32 o, size_t i, size_t m)
{
	(void)o; (void)i; (void)m;
	return &g_heap_tag;
}
W static BOOL HeapDestroy(HANDLE h) { (void)h; return 1; }

W static void *HeapAlloc(HANDLE h, u32 flags, size_t n)
{
	(void)h;
	if (!n)
		n = 1;
	return (flags & HEAP_ZERO) ? calloc(1, n) : malloc(n);
}

W static void *HeapReAlloc(HANDLE h, u32 flags, void *p, size_t n)
{
	size_t old;
	void *r;

	(void)h;
	if (!p)
		return HeapAlloc(h, flags, n);
	old = malloc_usable_size(p);
	r = realloc(p, n ? n : 1);
	if (r && (flags & HEAP_ZERO) && n > old)
		memset((u8 *)r + old, 0, n - old);
	return r;
}

W static BOOL HeapFree(HANDLE h, u32 f, void *p)
{
	(void)h; (void)f;
	free(p);
	return 1;
}

W static size_t HeapSize(HANDLE h, u32 f, void *p)
{
	(void)h; (void)f;
	return p ? malloc_usable_size(p) : (size_t)-1;
}

W static HANDLE LocalAlloc(u32 f, size_t n)
{
	return (f & 0x40) ? calloc(1, n ? n : 1) : malloc(n ? n : 1);
}
W static HANDLE LocalFree(HANDLE p) { free(p); return NULL; }

W static HANDLE GetStdHandle(i32 n)
{
	switch (n) {
	case -10: return fd2h(0);
	case -11: return fd2h(1);
	case -12: return fd2h(2);
	}
	set_err(87);
	return (HANDLE)(i64)-1;
}

W static BOOL SetStdHandle(i32 n, HANDLE h) { (void)n; (void)h; return 1; }

W static u32 GetFileType(HANDLE h)
{
	struct stat st;
	int fd = h2fd(h);

	if (fd < 0 || fstat(fd, &st) < 0)
		return 0;
	if (S_ISCHR(st.st_mode))
		return 2;
	if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode))
		return 3;
	return 1;
}

W static BOOL GetConsoleMode(HANDLE h, u32 *m)
{
	int fd = h2fd(h);

	if (fd < 0 || !isatty(fd)) {
		set_err(6);
		return 0;
	}
	*m = 3;
	return 1;
}

W static u32 GetConsoleCP(void) { return 65001; }
W static u32 GetConsoleOutputCP(void) { return 65001; }

W static BOOL WriteFile(HANDLE h, const void *buf, u32 n, u32 *written, void *ov)
{
	int fd = h2fd(h);
	ssize_t r;
	const u8 *p = buf;
	u32 total = 0;

	(void)ov;
	if (fd < 0) {
		set_err(6);
		return 0;
	}
	while (total < n) {
		r = write(fd, p + total, n - total);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			set_err(errno_to_win(errno));
			if (written)
				*written = total;
			return 0;
		}
		total += r;
	}
	if (written)
		*written = total;
	return 1;
}

W static BOOL WriteConsoleW(HANDLE h, const WCHAR *buf, u32 n, u32 *written, void *r)
{
	size_t m = utf16_to_utf8(buf, n, NULL, 0);
	u8 *tmp = malloc(m + 1);
	u32 w;
	BOOL ok;

	(void)r;
	utf16_to_utf8(buf, n, tmp, m);
	ok = WriteFile(h, tmp, m, &w, NULL);
	free(tmp);
	if (written)
		*written = n;
	return ok;
}

W static BOOL ReadFile(HANDLE h, void *buf, u32 n, u32 *rd, void *ov)
{
	int fd = h2fd(h);
	ssize_t r;

	(void)ov;
	if (fd < 0) {
		set_err(6);
		return 0;
	}
	r = read(fd, buf, n);
	if (r < 0) {
		set_err(errno_to_win(errno));
		return 0;
	}
	if (rd)
		*rd = r;
	return 1;
}

W static BOOL FlushFileBuffers(HANDLE h) { (void)h; return 1; }

W static BOOL CloseHandle(HANDLE h)
{
	int fd = h2fd(h);

	if (fd > 2)
		close(fd);
	return 1;
}

W static HANDLE CreateFileW(const WCHAR *name, u32 access, u32 share, void *sa,
			    u32 disp, u32 flags, HANDLE tmpl)
{
	char *path = wide_dup(name);
	int of = 0, fd;

	(void)share; (void)sa; (void)flags; (void)tmpl;
	if ((access & 0x40000000) && (access & 0x80000000))
		of = O_RDWR;
	else if (access & 0x40000000)
		of = O_WRONLY;
	else
		of = O_RDONLY;
	switch (disp) {
	case 1: of |= O_CREAT | O_EXCL; break;
	case 2: of |= O_CREAT | O_TRUNC; break;
	case 3: break;
	case 4: of |= O_CREAT; break;
	case 5: of |= O_TRUNC; break;
	}
	fd = open(path, of, 0644);
	free(path);
	if (fd < 0) {
		set_err(errno_to_win(errno));
		return (HANDLE)(i64)-1;
	}
	return fd2h(fd);
}

W static u32 SetFilePointer(HANDLE h, i32 lo, i32 *hi, u32 method)
{
	int fd = h2fd(h);
	i64 off = lo;
	off_t r;

	if (hi)
		off |= (i64)*hi << 32;
	r = lseek(fd, off, method == 0 ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END);
	if (r < 0)
		return 0xFFFFFFFF;
	if (hi)
		*hi = r >> 32;
	return (u32)r;
}

W static BOOL SetFilePointerEx(HANDLE h, i64 off, i64 *np, u32 method)
{
	off_t r = lseek(h2fd(h), off, method == 0 ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END);

	if (r < 0)
		return 0;
	if (np)
		*np = r;
	return 1;
}

W static BOOL SetEndOfFile(HANDLE h)
{
	int fd = h2fd(h);
	off_t p = lseek(fd, 0, SEEK_CUR);

	return ftruncate(fd, p) == 0;
}

W static void InitializeCriticalSection(void *cs) { memset(cs, 0, 40); }
W static BOOL InitializeCriticalSectionAndSpinCount(void *cs, u32 sc)
{
	(void)sc;
	memset(cs, 0, 40);
	return 1;
}
W static BOOL InitializeCriticalSectionEx(void *cs, u32 sc, u32 f)
{
	(void)sc; (void)f;
	memset(cs, 0, 40);
	return 1;
}
W static void EnterCriticalSection(void *cs) { (void)cs; }
W static void LeaveCriticalSection(void *cs) { (void)cs; }
W static BOOL TryEnterCriticalSection(void *cs) { (void)cs; return 1; }
W static void DeleteCriticalSection(void *cs) { (void)cs; }
W static void InitializeSListHead(void *h) { memset(h, 0, 16); }

#define NSLOTS 256
static void *g_fls[NSLOTS];
static u8 g_fls_used[NSLOTS];

W static u32 FlsAlloc(void *cb)
{
	u32 i;

	(void)cb;
	for (i = 0; i < NSLOTS; i++) {
		if (!g_fls_used[i]) {
			g_fls_used[i] = 1;
			g_fls[i] = NULL;
			return i;
		}
	}
	set_err(8);
	return 0xFFFFFFFF;
}
W static BOOL FlsFree(u32 i)
{
	if (i >= NSLOTS)
		return 0;
	g_fls_used[i] = 0;
	g_fls[i] = NULL;
	return 1;
}
W static void *FlsGetValue(u32 i)
{
	set_err(0);
	return i < NSLOTS ? g_fls[i] : NULL;
}
W static BOOL FlsSetValue(u32 i, void *v)
{
	if (i >= NSLOTS)
		return 0;
	g_fls[i] = v;
	return 1;
}

W static void RtlCaptureContext(void *ctx) { memset(ctx, 0, 1232); }
W static void *RtlLookupFunctionEntry(u64 pc, u64 *base, void *h)
{
	(void)pc; (void)h;
	if (base)
		*base = 0;
	return NULL;
}
W static void *RtlVirtualUnwind(u32 t, u64 b, u64 pc, void *f, void *c, void **hd, u64 *ef, void *cp)
{
	(void)t; (void)b; (void)pc; (void)f; (void)c; (void)hd; (void)ef; (void)cp;
	return NULL;
}
W static void RtlUnwindEx(void *a, void *b, void *c, void *d, void *e, void *f)
{
	(void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
}
W static void *RtlPcToFileHeader(void *pc, void **base)
{
	(void)pc;
	*base = g_base;
	return g_base;
}
W static void RaiseException(u32 code, u32 fl, u32 n, const u64 *a)
{
	(void)fl; (void)n; (void)a;
	fprintf(stderr, "peld: RaiseException(0x%x)\n", code);
	fflush(NULL);
	_exit(3);
}

W static u32 GetModuleFileNameA(HANDLE m, char *buf, u32 n)
{
	size_t l = strlen(g_path);

	(void)m;
	if (l >= n)
		l = n - 1;
	memcpy(buf, g_path, l);
	buf[l] = 0;
	return l;
}

W static u32 GetModuleFileNameW(HANDLE m, WCHAR *buf, u32 n)
{
	size_t l = utf8_to_utf16((u8 *)g_path, strlen(g_path), NULL, 0);

	(void)m;
	if (l >= n)
		l = n - 1;
	utf8_to_utf16((u8 *)g_path, strlen(g_path), buf, l);
	buf[l] = 0;
	return l;
}

static int is_builtin_dll(const char *n)
{
	static const char *const names[] = {
		"kernel32", "kernelbase", "ntdll", "user32", "advapi32",
		"shlwapi", "ucrtbase", "vcruntime140", "msvcrt", NULL
	};
	char b[64];
	size_t i, l = strlen(n);

	if (l >= sizeof b)
		return 0;
	for (i = 0; i < l; i++)
		b[i] = tolower((u8)n[i]);
	b[l] = 0;
	if (l > 4 && !strcmp(b + l - 4, ".dll"))
		b[l - 4] = 0;
	if (!strncmp(b, "api-ms-win-", 11))
		return 1;
	for (i = 0; names[i]; i++)
		if (!strcmp(b, names[i]))
			return 1;
	return 0;
}

struct ex { const char *name; void *fn; };
static const struct ex *find_export(const char *name);

W static HANDLE GetModuleHandleW(const WCHAR *name)
{
	char *n;
	int ok;

	if (!name)
		return g_base;
	n = wide_dup(name);
	ok = is_builtin_dll(n);
	free(n);
	return ok ? (HANDLE)(g_base + 0x1000000000ULL) : NULL;
}

W static HANDLE GetModuleHandleA(const char *name)
{
	if (!name)
		return g_base;
	return is_builtin_dll(name) ? (HANDLE)(g_base + 0x1000000000ULL) : NULL;
}

W static BOOL GetModuleHandleExW(u32 f, const WCHAR *name, HANDLE *out)
{
	HANDLE h = GetModuleHandleW(name);

	(void)f;
	if (!h)
		return 0;
	*out = h;
	return 1;
}

W static HANDLE LoadLibraryW(const WCHAR *name)
{
	HANDLE h = GetModuleHandleW(name);

	if (!h)
		set_err(126);
	return h;
}
W static HANDLE LoadLibraryExW(const WCHAR *name, HANDLE f, u32 fl)
{
	(void)f; (void)fl;
	return LoadLibraryW(name);
}
W static BOOL FreeLibrary(HANDLE h) { (void)h; return 1; }

W static void *GetProcAddress(HANDLE m, const char *name)
{
	const struct ex *e;

	(void)m;
	if ((u64)name < 0x10000)
		return NULL;
	e = find_export(name);
	if (!e) {
		set_err(127);
		return NULL;
	}
	return e->fn;
}

static WCHAR *g_envw;
W static WCHAR *GetEnvironmentStringsW(void)
{
	size_t total = 1, i, o = 0;
	WCHAR *r;

	for (i = 0; environ[i]; i++)
		total += utf8_to_utf16((u8 *)environ[i], strlen(environ[i]), NULL, 0) + 1;
	r = malloc(total * sizeof(WCHAR));
	for (i = 0; environ[i]; i++) {
		size_t l = utf8_to_utf16((u8 *)environ[i], strlen(environ[i]), r + o, total - o);
		o += l;
		r[o++] = 0;
	}
	r[o] = 0;
	g_envw = r;
	return r;
}
W static BOOL FreeEnvironmentStringsW(WCHAR *p) { free(p); return 1; }

W static char *GetEnvironmentStringsA(void)
{
	size_t total = 1, i, o = 0;
	char *r;

	for (i = 0; environ[i]; i++)
		total += strlen(environ[i]) + 1;
	r = malloc(total);
	for (i = 0; environ[i]; i++) {
		size_t l = strlen(environ[i]) + 1;
		memcpy(r + o, environ[i], l);
		o += l;
	}
	r[o] = 0;
	return r;
}
W static BOOL FreeEnvironmentStringsA(char *p) { free(p); return 1; }

W static u32 GetEnvironmentVariableW(const WCHAR *name, WCHAR *buf, u32 n)
{
	char *k = wide_dup(name);
	const char *v = getenv(k);
	size_t l;

	free(k);
	if (!v) {
		set_err(203);
		return 0;
	}
	l = utf8_to_utf16((u8 *)v, strlen(v), NULL, 0);
	if (l + 1 > n)
		return l + 1;
	utf8_to_utf16((u8 *)v, strlen(v), buf, l);
	buf[l] = 0;
	return l;
}

W static BOOL SetEnvironmentVariableW(const WCHAR *name, const WCHAR *val)
{
	char *k = wide_dup(name);
	int r;

	if (val) {
		char *v = wide_dup(val);
		r = setenv(k, v, 1);
		free(v);
	} else {
		r = unsetenv(k);
	}
	free(k);
	return r == 0;
}

W static char *GetCommandLineA(void) { return g_cmdline_a; }
W static WCHAR *GetCommandLineW(void) { return g_cmdline_w; }

W static void GetStartupInfoW(void *si)
{
	memset(si, 0, 104);
	*(u32 *)si = 104;
}
W static void GetStartupInfoA(void *si)
{
	memset(si, 0, 104);
	*(u32 *)si = 104;
}

W static void GetSystemInfo(u8 *si)
{
	memset(si, 0, 48);
	*(u16 *)si = 9;
	*(u32 *)(si + 4) = 4096;
	*(u64 *)(si + 8) = 0x10000;
	*(u64 *)(si + 16) = 0x7FFFFFFEFFFFULL;
	*(u64 *)(si + 24) = 1;
	*(u32 *)(si + 32) = 1;
	*(u32 *)(si + 36) = 8664;
	*(u32 *)(si + 40) = 0x10000;
}

W static u32 GetACP(void) { return 1252; }
W static u32 GetOEMCP(void) { return 437; }
W static BOOL IsValidCodePage(u32 cp) { (void)cp; return 1; }

W static BOOL GetCPInfo(u32 cp, u8 *info)
{
	(void)cp;
	memset(info, 0, 20);
	*(u32 *)info = 1;
	info[4] = '?';
	return 1;
}

W static i32 MultiByteToWideChar(u32 cp, u32 fl, const char *s, i32 n, WCHAR *d, i32 cap)
{
	size_t len = n < 0 ? strlen(s) + 1 : (size_t)n;
	size_t need = utf8_to_utf16((const u8 *)s, len, NULL, 0);

	(void)cp; (void)fl;
	if (!cap)
		return need;
	if ((i32)need > cap) {
		set_err(122);
		return 0;
	}
	utf8_to_utf16((const u8 *)s, len, d, cap);
	return need;
}

W static i32 WideCharToMultiByte(u32 cp, u32 fl, const WCHAR *s, i32 n, char *d, i32 cap,
				 const char *def, BOOL *used)
{
	size_t len = n < 0 ? u16len(s) + 1 : (size_t)n;
	size_t need = utf16_to_utf8(s, len, NULL, 0);

	(void)cp; (void)fl; (void)def;
	if (used)
		*used = 0;
	if (!cap)
		return need;
	if ((i32)need > cap) {
		set_err(122);
		return 0;
	}
	utf16_to_utf8(s, len, (u8 *)d, cap);
	return need;
}

W static BOOL GetStringTypeW(u32 type, const WCHAR *s, i32 n, u16 *out)
{
	i32 i;

	if (n < 0)
		n = u16len(s) + 1;
	for (i = 0; i < n; i++) {
		u32 c = s[i];
		u16 f = 0;

		if (c < 128) {
			if (isupper(c)) f |= 0x101;
			if (islower(c)) f |= 0x102;
			if (isdigit(c)) f |= 0x4;
			if (isspace(c)) f |= 0x8;
			if (ispunct(c)) f |= 0x10;
			if (iscntrl(c)) f |= 0x20;
			if (c == ' ' || c == '\t') f |= 0x40;
			if (isxdigit(c)) f |= 0x80;
		}
		out[i] = type == 1 ? f : 0;
	}
	return 1;
}

W static i32 LCMapStringW(u32 loc, u32 fl, const WCHAR *s, i32 n, WCHAR *d, i32 cap)
{
	i32 i;

	(void)loc;
	if (n < 0)
		n = u16len(s) + 1;
	if (!cap)
		return n;
	if (n > cap) {
		set_err(122);
		return 0;
	}
	for (i = 0; i < n; i++) {
		WCHAR c = s[i];

		if ((fl & 0x200) && c < 128)
			c = toupper(c);
		else if ((fl & 0x100) && c < 128)
			c = tolower(c);
		d[i] = c;
	}
	return n;
}

W static i32 CompareStringW(u32 loc, u32 fl, const WCHAR *a, i32 na, const WCHAR *b, i32 nb)
{
	i32 i, n;

	(void)loc;
	if (na < 0)
		na = u16len(a);
	if (nb < 0)
		nb = u16len(b);
	n = na < nb ? na : nb;
	for (i = 0; i < n; i++) {
		u32 x = a[i], y = b[i];

		if ((fl & 1) && x < 128 && y < 128) {
			x = tolower(x);
			y = tolower(y);
		}
		if (x != y)
			return x < y ? 1 : 3;
	}
	return na == nb ? 2 : na < nb ? 1 : 3;
}

W static u32 GetTempPathW(u32 n, WCHAR *buf)
{
	static const char t[] = "/tmp/";
	size_t l = sizeof t - 1;

	if (n < l + 1)
		return l + 1;
	utf8_to_utf16((const u8 *)t, l, buf, l);
	buf[l] = 0;
	return l;
}

W static BOOL SetCurrentDirectoryW(const WCHAR *p)
{
	char *s = wide_dup(p);
	int r = chdir(s);

	free(s);
	return r == 0;
}

W static u32 FormatMessageW(u32 f, const void *s, u32 id, u32 lang, WCHAR *buf, u32 n, void *a)
{
	(void)f; (void)s; (void)id; (void)lang; (void)buf; (void)n; (void)a;
	return 0;
}

W static u32 WaitForSingleObjectEx(HANDLE h, u32 ms, BOOL a)
{
	(void)h; (void)ms; (void)a;
	return 0;
}


typedef __builtin_ms_va_list msva;

struct sbuf { char *p; size_t n, cap; };

static void sb_put(struct sbuf *b, const char *s, size_t n)
{
	if (b->n + n + 1 > b->cap) {
		b->cap = (b->n + n + 1) * 2;
		b->p = realloc(b->p, b->cap);
	}
	memcpy(b->p + b->n, s, n);
	b->n += n;
	b->p[b->n] = 0;
}

static void sb_putf(struct sbuf *b, const char *spec, ...)
{
	char *r = NULL;
	va_list ap;
	int n;

	va_start(ap, spec);
	n = vasprintf(&r, spec, ap);
	va_end(ap);
	if (n >= 0) {
		sb_put(b, r, n);
		free(r);
	}
}

static char *wide_to_utf8_n(const WCHAR *w, size_t n)
{
	size_t m = utf16_to_utf8(w, n, NULL, 0);
	char *r = malloc(m + 1);

	utf16_to_utf8(w, n, (u8 *)r, m);
	r[m] = 0;
	return r;
}

static char *ms_vformat(const char *f, msva ap, size_t *outlen)
{
	struct sbuf b = { NULL, 0, 0 };

	sb_put(&b, "", 0);
	while (*f) {
		char flags[8] = "", spec[48];
		int width = -1, prec = -1, ll = 0, h = 0, wide = 0, nf = 0;
		char conv;

		if (*f != '%') {
			const char *s = f;

			while (*f && *f != '%')
				f++;
			sb_put(&b, s, f - s);
			continue;
		}
		f++;
		while (*f == '-' || *f == '+' || *f == ' ' || *f == '#' || *f == '0') {
			if (nf < 5)
				flags[nf++] = *f;
			f++;
		}
		flags[nf] = 0;
		if (*f == '*') {
			width = __builtin_va_arg(ap, i32);
			if (width < 0) {
				if (nf < 5) {
					flags[nf++] = '-';
					flags[nf] = 0;
				}
				width = -width;
			}
			f++;
		} else if (isdigit((u8)*f)) {
			width = 0;
			while (isdigit((u8)*f))
				width = width * 10 + (*f++ - '0');
		}
		if (*f == '.') {
			f++;
			prec = 0;
			if (*f == '*') {
				prec = __builtin_va_arg(ap, i32);
				f++;
			} else {
				while (isdigit((u8)*f))
					prec = prec * 10 + (*f++ - '0');
			}
		}
		if (f[0] == 'h' && f[1] == 'h') { h = 2; f += 2; }
		else if (f[0] == 'h') { h = 1; f++; }
		else if (f[0] == 'l' && f[1] == 'l') { ll = 1; f += 2; }
		else if (f[0] == 'l' || f[0] == 'w') { wide = 1; f++; }
		else if (f[0] == 'z' || f[0] == 'j' || f[0] == 't') { ll = 1; f++; }
		else if (f[0] == 'I') {
			if (f[1] == '6' && f[2] == '4') { ll = 1; f += 3; }
			else if (f[1] == '3' && f[2] == '2') { f += 3; }
			else { ll = 1; f++; }
		} else if (f[0] == 'L') { f++; }
		conv = *f;
		if (!conv)
			break;
		f++;
		if (width > 4000)
			width = 4000;
		if (prec > 4000)
			prec = 4000;

		spec[0] = '%';
		spec[1] = 0;
		strcat(spec, flags);
		if (width >= 0)
			sprintf(spec + strlen(spec), "%d", width);
		if (prec >= 0)
			sprintf(spec + strlen(spec), ".%d", prec);

		switch (conv) {
		case '%':
			sb_put(&b, "%", 1);
			break;
		case 'd':
		case 'i': {
			i64 v = ll ? __builtin_va_arg(ap, i64) : (i64)__builtin_va_arg(ap, i32);

			if (h == 1) v = (short)v;
			if (h == 2) v = (signed char)v;
			strcat(spec, "lld");
			sb_putf(&b, spec, (long long)v);
			break;
		}
		case 'u': case 'x': case 'X': case 'o': {
			u64 v = ll ? __builtin_va_arg(ap, u64) : (u64)__builtin_va_arg(ap, u32);

			if (h == 1) v = (unsigned short)v;
			if (h == 2) v = (unsigned char)v;
			strcat(spec, "ll");
			spec[strlen(spec)] = conv;
			spec[strlen(spec) + 1] = 0;
			sb_putf(&b, spec, (unsigned long long)v);
			break;
		}
		case 'p': {
			u64 v = __builtin_va_arg(ap, u64);

			sb_putf(&b, "%016llX", (unsigned long long)v);
			break;
		}
		case 'c': case 'C': {
			u32 v = __builtin_va_arg(ap, u32);
			char tmp[8];

			if (wide || conv == 'C') {
				WCHAR w = v;
				size_t k = utf16_to_utf8(&w, 1, (u8 *)tmp, 7);

				tmp[k] = 0;
			} else {
				tmp[0] = (char)v;
				tmp[1] = 0;
			}
			strcat(spec, "s");
			if (!tmp[0] && !wide && conv == 'c')
				sb_put(&b, "", 0);
			else
				sb_putf(&b, spec, tmp);
			break;
		}
		case 's': case 'S': {
			const void *p = __builtin_va_arg(ap, const void *);
			char *tmp = NULL;
			const char *str;

			if (!p) {
				str = "(null)";
			} else if (wide || conv == 'S') {
				tmp = wide_to_utf8_n(p, u16len(p));
				str = tmp;
			} else {
				str = p;
			}
			strcat(spec, "s");
			sb_putf(&b, spec, str);
			free(tmp);
			break;
		}
		case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A': {
			double v = __builtin_va_arg(ap, double);

			spec[strlen(spec) + 1] = 0;
			spec[strlen(spec)] = conv;
			sb_putf(&b, spec, v);
			break;
		}
		case 'n':
			(void)__builtin_va_arg(ap, void *);
			break;
		default:
			sb_put(&b, "%", 1);
			sb_put(&b, &conv, 1);
			break;
		}
	}
	*outlen = b.n;
	return b.p;
}

struct msfile { int fd; };
static struct msfile g_iob[3] = { { 0 }, { 1 }, { 2 } };

W static void *__acrt_iob_func(u32 i) { return i < 3 ? &g_iob[i] : NULL; }

static int msfile_write(struct msfile *f, const char *p, size_t n)
{
	size_t t = 0;

	while (t < n) {
		ssize_t r = write(f->fd, p + t, n - t);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		t += r;
	}
	return 0;
}

W static i32 __stdio_common_vfprintf(u64 opt, struct msfile *f, const char *fmt, void *loc, msva ap)
{
	size_t n;
	char *s = ms_vformat(fmt, ap, &n);
	int r = msfile_write(f, s, n);

	(void)opt; (void)loc;
	free(s);
	return r < 0 ? -1 : (i32)n;
}

W static i32 __stdio_common_vsprintf(u64 opt, char *buf, size_t cap, const char *fmt, void *loc, msva ap)
{
	size_t n;
	char *s = ms_vformat(fmt, ap, &n);

	(void)opt; (void)loc;
	if (buf && cap) {
		size_t c = n < cap - 1 ? n : cap - 1;

		memcpy(buf, s, c);
		buf[c] = 0;
	}
	free(s);
	return (i32)n;
}

W static i32 u_vfprintf(struct msfile *f, const char *fmt, msva ap)
{
	return __stdio_common_vfprintf(0, f, fmt, NULL, ap);
}

W static i32 u_fprintf(struct msfile *f, const char *fmt, ...)
{
	msva ap;
	i32 r;

	__builtin_ms_va_start(ap, fmt);
	r = u_vfprintf(f, fmt, ap);
	__builtin_ms_va_end(ap);
	return r;
}

W static size_t u_fwrite(const void *p, size_t sz, size_t n, struct msfile *f)
{
	return msfile_write(f, p, sz * n) < 0 ? 0 : n;
}

W static i32 u_fputc(i32 c, struct msfile *f)
{
	char ch = c;

	return msfile_write(f, &ch, 1) < 0 ? -1 : (u8)ch;
}

W static i32 u_puts(const char *s)
{
	if (msfile_write(&g_iob[1], s, strlen(s)) < 0 || msfile_write(&g_iob[1], "\n", 1) < 0)
		return -1;
	return 1;
}

W static i32 u_putchar(i32 c) { return u_fputc(c, &g_iob[1]); }

#define MAXEXIT 64
static void (W *g_atexit[MAXEXIT])(void);
static int g_natexit;
static int g_argc;
static char **g_argv;
static char **g_wargv_null;
static char **g_wenv_null;
static int g_fmode, g_commode, g_daylight, g_timezone;
static char *g_tzname[2] = { "UTC", "UTC" };
static u8 g_exc[16];

static void run_atexit(void)
{
	while (g_natexit > 0) {
		void (W *fn)(void) = g_atexit[--g_natexit];

		if (fn)
			fn();
	}
}

W static void u_exit(i32 code)
{
	run_atexit();
	fflush(NULL);
	_exit(code & 0xff);
}
W static void u__exit(i32 code)
{
	fflush(NULL);
	_exit(code & 0xff);
}
W static void u_cexit(void) { run_atexit(); }
W static void u_abort(void)
{
	fflush(NULL);
	abort();
}
W static i32 u_crt_atexit(void (W *fn)(void))
{
	if (g_natexit >= MAXEXIT)
		return -1;
	g_atexit[g_natexit++] = fn;
	return 0;
}
W static i32 u_register_onexit_function(void *t, void (W *fn)(void))
{
	(void)t;
	return u_crt_atexit(fn);
}
W static i32 u_initialize_onexit_table(void *t)
{
	memset(t, 0, 24);
	return 0;
}
W static i32 u_execute_onexit_table(void *t)
{
	(void)t;
	run_atexit();
	return 0;
}
W static i32 u_noop_zero(void) { return 0; }
W static void u_noop(void) { }
W static void u_initterm(void (W **s)(void), void (W **e)(void))
{
	for (; s < e; s++)
		if (*s)
			(*s)();
}
W static i32 u_initterm_e(i32 (W **s)(void), i32 (W **e)(void))
{
	for (; s < e; s++) {
		i32 r;

		if (*s && (r = (*s)()))
			return r;
	}
	return 0;
}
W static i32 *u_p_argc(void) { return &g_argc; }
W static char ***u_p_argv(void) { return &g_argv; }
W static char ***u_p_wargv(void) { return &g_wargv_null; }
W static char ***u_p_environ(void) { return &environ; }
W static char ***u_p_wenviron(void) { return &g_wenv_null; }
W static char **u_get_initial_narrow_environment(void) { return environ; }
W static i32 *u_p_fmode(void) { return &g_fmode; }
W static i32 *u_p_commode(void) { return &g_commode; }
W static i32 *u_p_daylight(void) { return &g_daylight; }
W static i32 *u_p_timezone(void) { return &g_timezone; }
W static char **u_p_tzname(void) { return g_tzname; }
W static void *u_current_exception(void) { return g_exc; }
W static i32 u_set_app_type(i32 t) { (void)t; return 0; }
W static i32 u_set_new_mode(i32 m) { (void)m; return 0; }
W static i32 u_configure_narrow_argv(i32 m)
{
	(void)m;
	return 0;
}
W static void *u_signal(i32 s, void *h) { (void)s; (void)h; return NULL; }
W static void *u_malloc(size_t n) { return malloc(n); }
W static void *u_calloc(size_t a, size_t b) { return calloc(a, b); }
W static void *u_realloc(void *p, size_t n) { return realloc(p, n); }
W static void u_free(void *p) { free(p); }
W static void *u_memcpy(void *d, const void *s, size_t n) { return memcpy(d, s, n); }
W static void *u_memmove(void *d, const void *s, size_t n) { return memmove(d, s, n); }
W static void *u_memset(void *d, i32 c, size_t n) { return memset(d, c, n); }
W static i32 u_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n); }
W static size_t u_strlen(const char *s) { return strlen(s); }
W static size_t u_wcslen(const WCHAR *s) { return u16len(s); }
W static i32 u_strcmp(const char *a, const char *b) { return strcmp(a, b); }
W static i32 u_strncmp(const char *a, const char *b, size_t n) { return strncmp(a, b, n); }
W static char *u_strcpy(char *d, const char *s) { return strcpy(d, s); }
W static char *u_strncpy(char *d, const char *s, size_t n) { return strncpy(d, s, n); }
W static char *u_strchr(const char *s, i32 c) { return (char *)strchr(s, c); }
W static i32 u_C_specific_handler(void) { return 1; }
W static i32 u_seh_filter_exe(void) { return 0; }

static void init_crt_args(int argc, char **argv)
{
	int i;

	g_argc = argc + 1;
	g_argv = calloc(g_argc + 1, sizeof(char *));
	g_argv[0] = g_path;
	for (i = 0; i < argc; i++)
		g_argv[i + 1] = argv[i];
}

#define UX(n) { #n, (void *)u_##n }
#define UXN(n, f) { n, (void *)f }


W static void *AddVectoredExceptionHandler(u32 first, void *h)
{
	(void)first;
	return h ? h : (void *)1;
}
W static u32 RemoveVectoredExceptionHandler(void *h) { (void)h; return 1; }
W static BOOL SetThreadStackGuarantee(u32 *size) { (void)size; return 1; }
W static void GetSystemTimePreciseAsFileTime(u64 *ft) { GetSystemTimeAsFileTime(ft); }

static void *g_tls[NSLOTS];
static u8 g_tls_used[NSLOTS];

W static u32 TlsAlloc(void)
{
	u32 i;

	for (i = 0; i < NSLOTS; i++) {
		if (!g_tls_used[i]) {
			g_tls_used[i] = 1;
			g_tls[i] = NULL;
			return i;
		}
	}
	return 0xFFFFFFFF;
}
W static BOOL TlsFree(u32 i)
{
	if (i >= NSLOTS)
		return 0;
	g_tls_used[i] = 0;
	return 1;
}
W static void *TlsGetValue(u32 i)
{
	set_err(0);
	return i < NSLOTS ? g_tls[i] : NULL;
}
W static BOOL TlsSetValue(u32 i, void *v)
{
	if (i >= NSLOTS)
		return 0;
	g_tls[i] = v;
	return 1;
}

W static BOOL ProcessPrng(u8 *buf, size_t n)
{
	size_t t = 0;

	while (t < n) {
		ssize_t r = syscall(SYS_getrandom, buf + t, n - t, 0);

		if (r <= 0)
			break;
		t += r;
	}
	return 1;
}
W static u8 RtlGenRandom(u8 *buf, u32 n) { return ProcessPrng(buf, n); }

W static i32 RtlGetVersion(u8 *info)
{
	memset(info + 4, 0, 16);
	*(u32 *)(info + 4) = 10;
	*(u32 *)(info + 12) = 19045;
	*(u32 *)(info + 16) = 2;
	return 0;
}

W static u32 GetCurrentDirectoryW(u32 n, WCHAR *buf)
{
	char cwd[4096];
	size_t l;

	if (!getcwd(cwd, sizeof cwd))
		return 0;
	l = utf8_to_utf16((u8 *)cwd, strlen(cwd), NULL, 0);
	if (l + 1 > n)
		return l + 1;
	utf8_to_utf16((u8 *)cwd, strlen(cwd), buf, l);
	buf[l] = 0;
	return l;
}

W static u32 WaitForSingleObject(HANDLE h, u32 ms) { (void)h; (void)ms; return 0; }
W static i32 SetThreadDescription(HANDLE h, const WCHAR *d) { (void)h; (void)d; return 0; }
W static BOOL GetConsoleScreenBufferInfo(HANDLE h, void *i) { (void)h; (void)i; return 0; }
W static void OutputDebugStringA(const char *s) { (void)s; }
W static void OutputDebugStringW(const WCHAR *s) { (void)s; }
W static BOOL DuplicateHandle(HANDLE a, HANDLE src, HANDLE b, HANDLE *dst, u32 c, BOOL d, u32 e)
{
	(void)a; (void)b; (void)c; (void)d; (void)e;
	*dst = src;
	return 1;
}
W static void GetNativeSystemInfo(u8 *si) { GetSystemInfo(si); }
W static void SRWNoop(void *l) { (void)l; }
W static u8 SRWTry(void *l) { (void)l; return 1; }
W static BOOL WaitOnAddress(void *a, void *b, size_t n, u32 ms)
{
	(void)a; (void)b; (void)n; (void)ms;
	return 1;
}
W static void WakeByAddress(void *a) { (void)a; }


W static HANDLE LoadLibraryA(const char *name)
{
	HANDLE h = GetModuleHandleA(name);

	if (!h)
		set_err(126);
	return h;
}
W static i32 lstrlenW(const WCHAR *s) { return s ? (i32)u16len(s) : 0; }
W static HANDLE CreateMutexA(void *sa, BOOL owner, const char *name)
{
	(void)sa; (void)owner; (void)name;
	return calloc(1, 16);
}
W static BOOL ReleaseMutex(HANDLE h) { (void)h; return 1; }

W static i32 NtWriteFile(HANDLE h, HANDLE ev, void *apc, void *ctx, u64 *iosb,
			 const void *buf, u32 len, void *off, void *key)
{
	int fd = h2fd(h);
	u32 done = 0;

	(void)ev; (void)apc; (void)ctx; (void)off; (void)key;
	if (fd < 0)
		return (i32)0xC0000008;
	while (done < len) {
		ssize_t r = write(fd, (const u8 *)buf + done, len - done);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			if (iosb) {
				iosb[0] = 0xC0000185;
				iosb[1] = done;
			}
			return (i32)0xC0000185;
		}
		done += r;
	}
	if (iosb) {
		iosb[0] = 0;
		iosb[1] = done;
	}
	return 0;
}

W static u32 RtlNtStatusToDosError(i32 st)
{
	switch ((u32)st) {
	case 0: return 0;
	case 0xC0000008: return 6;
	case 0xC0000022: return 5;
	case 0xC000000D: return 87;
	case 0xC0000034: return 2;
	case 0xC0000185: return 1117;
	default: return 317;
	}
}

W static i32 u_CxxFrameHandler3(void) { return 1; }

#define EX(n) { #n, (void *)n }
static const struct ex g_exports[] = {
	EX(ExitProcess), EX(TerminateProcess), EX(GetCurrentProcess), EX(GetCurrentThread),
	EX(GetCurrentProcessId), EX(GetCurrentThreadId), EX(GetLastError), EX(SetLastError),
	EX(GetVersion), EX(IsDebuggerPresent), EX(EncodePointer), EX(DecodePointer),
	EX(SetUnhandledExceptionFilter), EX(UnhandledExceptionFilter), EX(SetConsoleCtrlHandler),
	EX(SetHandleCount), EX(HeapSetInformation), EX(IsProcessorFeaturePresent), EX(Sleep),
	EX(GetSystemTimeAsFileTime), EX(QueryPerformanceCounter), EX(QueryPerformanceFrequency),
	EX(GetTickCount), EX(GetTickCount64), EX(GetProcessHeap), EX(HeapCreate), EX(HeapDestroy),
	EX(HeapAlloc), EX(HeapReAlloc), EX(HeapFree), EX(HeapSize), EX(LocalAlloc), EX(LocalFree),
	EX(GetStdHandle), EX(SetStdHandle), EX(GetFileType), EX(GetConsoleMode), EX(GetConsoleCP),
	EX(GetConsoleOutputCP), EX(WriteFile), EX(WriteConsoleW), EX(ReadFile), EX(FlushFileBuffers),
	EX(CloseHandle), EX(CreateFileW), EX(SetFilePointer), EX(SetFilePointerEx), EX(SetEndOfFile),
	EX(InitializeCriticalSection), EX(InitializeCriticalSectionAndSpinCount),
	EX(InitializeCriticalSectionEx), EX(EnterCriticalSection), EX(LeaveCriticalSection),
	EX(TryEnterCriticalSection), EX(DeleteCriticalSection), EX(InitializeSListHead),
	EX(FlsAlloc), EX(FlsFree), EX(FlsGetValue), EX(FlsSetValue),
	EX(RtlCaptureContext), EX(RtlLookupFunctionEntry), EX(RtlVirtualUnwind), EX(RtlUnwindEx),
	EX(RtlPcToFileHeader), EX(RaiseException),
	EX(GetModuleFileNameA), EX(GetModuleFileNameW), EX(GetModuleHandleW), EX(GetModuleHandleA),
	EX(GetModuleHandleExW), EX(LoadLibraryW), EX(LoadLibraryExW), EX(FreeLibrary),
	EX(GetProcAddress), EX(GetEnvironmentStringsW), EX(FreeEnvironmentStringsW),
	EX(GetEnvironmentStringsA), EX(FreeEnvironmentStringsA), EX(GetEnvironmentVariableW),
	EX(SetEnvironmentVariableW), EX(GetCommandLineA), EX(GetCommandLineW),
	EX(GetStartupInfoW), EX(GetStartupInfoA), EX(GetSystemInfo), EX(GetACP), EX(GetOEMCP),
	EX(IsValidCodePage), EX(GetCPInfo), EX(MultiByteToWideChar), EX(WideCharToMultiByte),
	EX(GetStringTypeW), EX(LCMapStringW), EX(CompareStringW), EX(GetTempPathW),
	EX(SetCurrentDirectoryW), EX(FormatMessageW), EX(WaitForSingleObjectEx),
	EX(__acrt_iob_func), EX(__stdio_common_vfprintf), EX(__stdio_common_vsprintf),
	UX(vfprintf), UX(fprintf), UX(fwrite), UX(fputc), UX(puts), UX(putchar),
	UX(exit), UXN("_exit", u__exit), UXN("_c_exit", u_cexit), UXN("_cexit", u_cexit), UX(abort),
	UXN("_crt_atexit", u_crt_atexit), UXN("_register_onexit_function", u_register_onexit_function),
	UXN("_initialize_onexit_table", u_initialize_onexit_table),
	UXN("_execute_onexit_table", u_execute_onexit_table),
	UXN("_initterm", u_initterm), UXN("_initterm_e", u_initterm_e),
	UXN("__p___argc", u_p_argc), UXN("__p___argv", u_p_argv), UXN("__p___wargv", u_p_wargv),
	UXN("__p__environ", u_p_environ), UXN("__p__wenviron", u_p_wenviron),
	UXN("_get_initial_narrow_environment", u_get_initial_narrow_environment),
	UXN("__p__fmode", u_p_fmode), UXN("__p__commode", u_p_commode),
	UXN("__daylight", u_p_daylight), UXN("__timezone", u_p_timezone), UXN("__tzname", u_p_tzname),
	UXN("__current_exception", u_current_exception),
	UXN("__current_exception_context", u_current_exception),
	UXN("_set_app_type", u_set_app_type), UXN("_set_new_mode", u_set_new_mode),
	UXN("_configure_narrow_argv", u_configure_narrow_argv),
	UXN("_configure_wide_argv", u_noop_zero), UXN("_initialize_narrow_environment", u_noop_zero),
	UXN("_initialize_wide_environment", u_noop_zero), UXN("_set_fmode", u_noop_zero),
	UXN("_set_invalid_parameter_handler", u_noop_zero), UXN("_fpreset", u_noop),
	UXN("_crt_at_quick_exit", u_noop_zero), UXN("_tzset", u_noop), UXN("_controlfp_s", u_noop_zero),
	UXN("_configthreadlocale", u_noop_zero), UXN("__setusermatherr", u_noop),
	UXN("_register_thread_local_exe_atexit_callback", u_noop),
	UXN("_invalid_parameter_noinfo_noreturn", u_abort), UXN("terminate", u_abort),
	UXN("_seh_filter_exe", u_seh_filter_exe), UXN("__C_specific_handler", u_C_specific_handler),
	UXN("__security_check_cookie", u_noop), UXN("_amsg_exit", u_abort),
	UX(signal), UX(malloc), UX(calloc), UX(realloc), UX(free), UX(memcpy), UX(memmove),
	UX(memset), UX(memcmp), UX(strlen), UX(wcslen), UX(strcmp), UX(strncmp), UX(strcpy),
	UX(strncpy), UX(strchr),
	EX(AddVectoredExceptionHandler), EX(RemoveVectoredExceptionHandler),
	EX(SetThreadStackGuarantee), EX(GetSystemTimePreciseAsFileTime),
	EX(TlsAlloc), EX(TlsFree), EX(TlsGetValue), EX(TlsSetValue),
	EX(ProcessPrng), EX(RtlGenRandom), UXN("SystemFunction036", RtlGenRandom),
	EX(RtlGetVersion), EX(GetCurrentDirectoryW), EX(WaitForSingleObject),
	EX(SetThreadDescription), EX(GetConsoleScreenBufferInfo), EX(OutputDebugStringA),
	EX(OutputDebugStringW), EX(DuplicateHandle), EX(GetNativeSystemInfo),
	UXN("AcquireSRWLockExclusive", SRWNoop), UXN("AcquireSRWLockShared", SRWNoop),
	UXN("ReleaseSRWLockExclusive", SRWNoop), UXN("ReleaseSRWLockShared", SRWNoop),
	UXN("TryAcquireSRWLockExclusive", SRWTry), UXN("TryAcquireSRWLockShared", SRWTry),
	EX(WaitOnAddress), UXN("WakeByAddressSingle", WakeByAddress),
	UXN("WakeByAddressAll", WakeByAddress),
	EX(LoadLibraryA), EX(lstrlenW), EX(CreateMutexA), EX(ReleaseMutex), EX(NtWriteFile),
	EX(RtlNtStatusToDosError), UXN("__CxxFrameHandler3", u_CxxFrameHandler3),
	UXN("__CxxFrameHandler4", u_CxxFrameHandler3),
	{ NULL, NULL }
};

static const struct ex *find_export(const char *name)
{
	const struct ex *e;

	for (e = g_exports; e->name; e++)
		if (!strcmp(e->name, name))
			return e;
	return NULL;
}

static u32 prot_of(u32 c)
{
	u32 p = 0;

	if (c & 0x40000000) p |= PROT_READ;
	if (c & 0x80000000) p |= PROT_WRITE;
	if (c & 0x20000000) p |= PROT_EXEC;
	return p;
}

static void *rva(u32 r)
{
	if (r >= g_image_size)
		fatal("rva out of range%s", "");
	return g_base + r;
}

static void apply_relocs(struct pe_opt *o, i64 delta)
{
	u32 off = 0, sz = o->dir[5].size;
	u8 *rb;

	if (!delta || !o->dir[5].rva)
		return;
	rb = rva(o->dir[5].rva);
	while (off + 8 <= sz) {
		u32 page = *(u32 *)(rb + off), blk = *(u32 *)(rb + off + 4);
		u32 i, n;

		if (blk < 8)
			break;
		n = (blk - 8) / 2;
		for (i = 0; i < n; i++) {
			u16 e = *(u16 *)(rb + off + 8 + i * 2);
			u32 t = e >> 12, a = page + (e & 0xFFF);

			if (t == 10)
				*(i64 *)rva(a) += delta;
			else if (t == 3)
				*(i32 *)rva(a) += (i32)delta;
			else if (t != 0)
				fatal("unsupported relocation type %s", "");
		}
		off += blk;
	}
}

static void resolve_imports(struct pe_opt *o)
{
	struct imp_desc *d;

	if (!o->dir[1].rva)
		return;
	for (d = rva(o->dir[1].rva); d->name || d->ft; d++) {
		const char *dll = rva(d->name);
		u64 *oft = rva(d->oft ? d->oft : d->ft);
		u64 *ft = rva(d->ft);

		for (; *oft; oft++, ft++) {
			const struct ex *e;
			const char *nm;
			char *buf;

			if (*oft >> 63) {
				buf = malloc(64 + strlen(dll));
				sprintf(buf, "%s!#%u", dll, (u32)(*oft & 0xFFFF));
				*ft = (u64)make_thunk(buf);
				continue;
			}
			nm = (const char *)rva((u32)*oft) + 2;
			e = find_export(nm);
			if (e) {
				*ft = (u64)e->fn;
			} else {
				buf = malloc(strlen(dll) + strlen(nm) + 2);
				sprintf(buf, "%s!%s", dll, nm);
				if (getenv("PELD_DEBUG"))
					fprintf(stderr, "peld: missing import %s\n", buf);
				*ft = (u64)make_thunk(buf);
			}
		}
	}
}

static void build_cmdline(int argc, char **argv)
{
	size_t cap = strlen(g_path) + 8, i;
	char *p;

	for (i = 0; i < (size_t)argc; i++)
		cap += strlen(argv[i]) * 2 + 4;
	g_cmdline_a = p = malloc(cap);
	p += sprintf(p, "\"%s\"", g_path);
	for (i = 0; i < (size_t)argc; i++) {
		if (strchr(argv[i], ' ') || !*argv[i])
			p += sprintf(p, " \"%s\"", argv[i]);
		else
			p += sprintf(p, " %s", argv[i]);
	}
	{
		size_t n = utf8_to_utf16((u8 *)g_cmdline_a, strlen(g_cmdline_a), NULL, 0);

		g_cmdline_w = malloc((n + 1) * sizeof(WCHAR));
		utf8_to_utf16((u8 *)g_cmdline_a, strlen(g_cmdline_a), g_cmdline_w, n);
		g_cmdline_w[n] = 0;
	}
}

static void setup_teb(u8 *image, void *stack_top)
{
	struct rlimit rl;
	u64 stack_size = 8 << 20;
	u8 *params;

	if (!getrlimit(RLIMIT_STACK, &rl) && rl.rlim_cur != RLIM_INFINITY)
		stack_size = rl.rlim_cur;
	g_teb = calloc(1, 0x2000);
	g_peb = calloc(1, 0x1000);
	params = calloc(1, 0x1000);
	if (!g_teb || !g_peb || !params)
		fatal("out of memory%s", "");
	*(u64 *)(g_teb + 0x00) = 0;
	*(u64 *)(g_teb + 0x08) = (u64)stack_top;
	*(u64 *)(g_teb + 0x10) = (u64)stack_top - stack_size + 0x10000;
	*(u64 *)(g_teb + 0x30) = (u64)g_teb;
	*(u64 *)(g_teb + 0x40) = getpid();
	*(u64 *)(g_teb + 0x48) = syscall(SYS_gettid);
	*(u64 *)(g_teb + 0x60) = (u64)g_peb;
	*(u64 *)(g_peb + 0x10) = (u64)image;
	*(u64 *)(g_peb + 0x20) = (u64)params;
	*(u64 *)(g_peb + 0x30) = (u64)&g_heap_tag;
	*(u32 *)(g_peb + 0xBC) = 0;
	*(u32 *)(g_peb + 0x118) = 10;
	*(u32 *)(g_peb + 0x11C) = 0;
	*(u32 *)(g_peb + 0x120) = 19045;
	*(u32 *)(g_peb + 0x124) = 2;
	if (syscall(SYS_arch_prctl, ARCH_SET_GS, g_teb))
		fatal("arch_prctl(ARCH_SET_GS) failed%s", "");
}

static void setup_tls(struct pe_opt *o)
{
	struct tls_dir *t;
	u64 size;
	u8 *blk;
	void **arr;
	u64 *cb;

	if (!o->dir[9].rva)
		return;
	t = rva(o->dir[9].rva);
	size = t->end - t->start;
	blk = calloc(1, size + t->zero + 16);
	memcpy(blk, (void *)t->start, size);
	arr = calloc(64, sizeof(void *));
	arr[0] = blk;
	*(u32 *)t->index = 0;
	*(void ***)(g_teb + 0x58) = arr;
	if (t->callbacks) {
		for (cb = (u64 *)t->callbacks; *cb; cb++)
			((W void (*)(void *, u32, void *))*cb)(g_base, 1, NULL);
	}
}

int main(int argc, char **argv)
{
	struct pe_opt opt;
	struct pe_file fh;
	struct pe_sec *secs;
	u8 hdr[4096];
	u32 pe_off, i, hdr_size;
	int fd;
	ssize_t rd;
	u8 *map;
	i64 delta;
	int vol;

	if (argc < 2)
		fatal("usage: peld program.exe [args...]%s", "");
	if (!realpath(argv[1], g_path))
		snprintf(g_path, sizeof g_path, "%s", argv[1]);
	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		fatal("cannot open %s", argv[1]);
	rd = pread(fd, hdr, sizeof hdr, 0);
	if (rd < 0x200 || hdr[0] != 'M' || hdr[1] != 'Z')
		fatal("not a PE file: %s", argv[1]);
	pe_off = *(u32 *)(hdr + 0x3C);
	if (pe_off + 24 + sizeof opt > sizeof hdr || memcmp(hdr + pe_off, "PE\0\0", 4))
		fatal("bad PE signature%s", "");
	memcpy(&fh, hdr + pe_off + 4, sizeof fh);
	if (fh.machine != 0x8664)
		fatal("not an AMD64 image%s", "");
	memcpy(&opt, hdr + pe_off + 24, sizeof opt);
	if (opt.magic != 0x20B)
		fatal("not PE32+%s", "");
	secs = (struct pe_sec *)(hdr + pe_off + 24 + fh.optsize);
	if ((u8 *)(secs + fh.nsec) > hdr + sizeof hdr)
		fatal("too many sections%s", "");

	g_image_size = (opt.size_image + 0xFFF) & ~0xFFFULL;
	map = mmap((void *)opt.image_base, g_image_size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
	if (map == MAP_FAILED || (u64)map != opt.image_base) {
		if (map != MAP_FAILED)
			munmap(map, g_image_size);
		map = mmap(NULL, g_image_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (map == MAP_FAILED)
			fatal("cannot map image%s", "");
	}
	g_base = map;
	delta = (i64)((u64)map - opt.image_base);

	hdr_size = opt.size_headers < sizeof hdr ? opt.size_headers : sizeof hdr;
	memcpy(map, hdr, hdr_size);
	for (i = 0; i < fh.nsec; i++) {
		u32 n = secs[i].rawsize < secs[i].vsize || !secs[i].vsize ? secs[i].rawsize : secs[i].vsize;

		if (secs[i].va + n > g_image_size)
			fatal("section out of range%s", "");
		if (n && pread(fd, map + secs[i].va, n, secs[i].rawptr) != (ssize_t)n)
			fatal("short read of section%s", "");
	}
	close(fd);

	apply_relocs(&opt, delta);
	resolve_imports(&opt);

	for (i = 0; i < fh.nsec; i++) {
		u32 sz = (secs[i].vsize + 0xFFF) & ~0xFFFu;
		u32 p = prot_of(secs[i].chars);

		if (sz && mprotect(map + secs[i].va, sz, p ? p : PROT_NONE))
			fatal("mprotect failed%s", "");
	}
	mprotect(map, 0x1000, PROT_READ);

	build_cmdline(argc - 2, argv + 2);
	init_crt_args(argc - 2, argv + 2);
	setup_teb(map, &vol);
	setup_tls(&opt);

	{
		int (W *entry)(void) = (int (W *)(void))(map + opt.entry);
		int code = entry();

		fflush(NULL);
		_exit(code & 0xff);
	}
}
