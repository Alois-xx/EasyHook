// UnmanagedWithExports.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <chrono>

extern "C" _declspec(noinline) int WINAPI Func0()
{
	printf("#Func0. No args\n");
	return 1234;
}


extern "C" _declspec(noinline) int WINAPI Func1(int *a)
{
	printf("#Func1. Input Arg Addresses: %p\n", a);
	*a = 1;
	return 1234;
}

extern "C" _declspec(noinline) int WINAPI FuncETW(int *a, int *b, int *c, int *d, int *e)
{
	*a = 1;
	*b = 2;
	*c = 3;
	*d = 4;
	*e = 5;
	return 1234;
}

extern "C" _declspec(noinline) int WINAPI Func4(int *a, int *b, int *c, int *d)
{
	printf("#Func4. Input Arg Addresses: %p %p %p %p\n", a, b, c, d);
	*a = 1;
	*b = 2;
	*c = 3;
	*d = 4;
	return 1234;
}

extern "C" _declspec(noinline) int WINAPI Func8(int *a, int *b, int *c, int *d, int *e, int *f, int *g, int *h)
{
	printf("#Func8. Input Arg Addresses: %p %p %p %p %p %p %p %p\n", a, b, c, d, e,f,g,h);

	*a = 1;
	*b = 2;
	*c = 3;
	*d = 4;
	*e = 5;
	*f = 6;
	*g = 7;
	*h = 8;
	return 1234;
}

extern "C" _declspec(noinline) int WINAPI Func9(int *a, int *b, int *c, int *d, int *e, int *f, int *g, int *h, int *i)
{
	printf("#Func9. Input Arg Addresses: %p %p %p %p %p %p %p %p %p\n", a, b, c, d, e, f, g, h,i);

	*a = 1;
	*b = 2;
	*c = 3;
	*d = 4;
	*e = 5;
	*f = 6;
	*g = 7;
	*h = 8;
	*i = 9;
	return 1234;
}




int main(int argc, char *argv[])
{
	int ETWFuncCount = 10 * 1000 * 1000;
	if (argc > 1)
	{
		ETWFuncCount = atoi(argv[1]);
		printf("\nAdjusted ETW func call count: %d", ETWFuncCount);
	}

	const int Pattern = 0x12345678;

	int a = Pattern,
		b = Pattern + 1,
		c = Pattern + 2,
		d = Pattern + 3,
		e = Pattern + 4,
		f = Pattern + 5,
		g = Pattern + 6,
		h = Pattern + 7,
		i = Pattern + 8;

	::Sleep(5000);

	for (int z = 0; z < 2; z++)
	{
		int lret = Func0();
		printf("#Func0 returned: %d\n", lret);
		lret = Func1(&a);
		printf("#Func1 = %d, Got: a: %X\n",lret, a);
		lret = Func4(&a, &b, &c, &d);
		printf("#Func4 = %d, Got: a: %X, b: %X, c: %X, d: %X\n",lret, a, b, c, d);
		lret = Func8(&a, &b, &c, &d, &e, &f, &g, &h);
		printf("#Func8 = %d, Got: a: %X, b: %X, c: %X, d: %X, e: %X, f: %X, g: %X, h: %X\n",lret, a, b, c, d, e, f, g, h);
		lret = Func9(&a, &b, &c, &d, &e, &f, &g, &h, &i);
		printf("#Func9 = %d, Got: a: %X, b: %X, c: %X, d: %X, e: %X, f: %X, g: %X, h: %X, i: %X\n",lret,  a, b, c, d, e, f, g, h, i);
	}

	a = b = c = d = e = 0;
	auto start = std::chrono::high_resolution_clock::now();
	for (int i = 0; i < ETWFuncCount; i++)
	{
		FuncETW(&a, &b, &c, &d, &e);
	}
	auto stop = std::chrono::high_resolution_clock::now();
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();
	printf("FuncETW %d iterations did take %I64dms, Average call Duration: %f us.\n", ETWFuncCount, ms, (ms*1000.0f) / ETWFuncCount);
	printf("Press Enter to exit.\n");
	getchar();
    return 0;
}


