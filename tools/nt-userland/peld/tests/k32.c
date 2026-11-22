#include <windows.h>
int mainCRTStartup(void)
{
	HANDLE o = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD n, mode, ft = GetFileType(o);
	static const char a[] = "Hello, world! (WriteFile)\r\n";
	static const WCHAR w[] = L"Hello, world! (WriteConsoleW) \x043f\x0440\x0438\x0432\x0435\x0442\r\n";
	char *h = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 64);
	DWORD fls = FlsAlloc(0);
	FILETIME t;
	LARGE_INTEGER q;

	FlsSetValue(fls, h);
	GetSystemTimeAsFileTime(&t);
	QueryPerformanceCounter(&q);
	WriteFile(o, a, sizeof a - 1, &n, 0);
	if (GetConsoleMode(o, &mode))
		WriteConsoleW(o, w, sizeof w / 2 - 1, &n, 0);
	ExitProcess(ft == 2 && h[10] == 0 && FlsGetValue(fls) == h && t.dwHighDateTime ? 0 : 9);
	return 0;
}
