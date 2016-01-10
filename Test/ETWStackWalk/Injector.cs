using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using EasyHook;
using System.Diagnostics;

namespace ETWStackwalk
{
    public unsafe class Injector : EasyHook.IEntryPoint
    {
        InterprocessInterface Interface;
        LocalHook CreateFileHook;
        LocalHook CreateWindowHook;
        LocalHook DestroyWindowHook;

        // Hooks for unit testing EeasyHook
        LocalHook Func0Hook;
        LocalHook Func1Hook;
        LocalHook Func4Hook;
        LocalHook Func8Hook;
        LocalHook Func9Hook;

        Stack<String> Queue = new Stack<String>();

        public Injector(RemoteHooking.IContext InContext, String InChannelName, List<string> hookedMethods)
        {
            // connect to host...
            Interface = RemoteHooking.IpcConnectClient<InterprocessInterface>(InChannelName);

            Interface.Ping();
        }

        public void Run(RemoteHooking.IContext InContext, String InChannelName, List<string> hookedMethods)
        {
            // install hook...
            try
            {
                Register(hookedMethods);
            }
            catch (Exception ExtInfo)
            {
                Interface.ReportException(ExtInfo);

                return;
            }

            Interface.IsInstalled(RemoteHooking.GetCurrentProcessId());

            RemoteHooking.WakeUpProcess();

            // wait for host process termination...
            try
            {
                while (true)
                {
                    Thread.Sleep(500);

                    // transmit newly monitored file accesses...
                    if (Queue.Count > 0)
                    {
                        String[] Package = null;

                        lock (Queue)
                        {
                            Package = Queue.ToArray();

                            Queue.Clear();
                        }

                        Interface.OnCreateFile(RemoteHooking.GetCurrentProcessId(), Package);
                    }
                    else
                        Interface.Ping();
                }
            }
            catch
            {
                // Ping() will raise an exception if host is unreachable
            }
        }

        private void Register(List<string> hookedMethods)
        {
            foreach (var hook in hookedMethods)
            {
                switch (hook)
                {
                    case Program.CreateFileHookName:
                        CreateFileHook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"), new DCreateFile(CreateFile_Hooked), this);
                        CreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
                        break;
                    case Program.CreateWindowHookName:
                        CreateWindowHook = LocalHook.Create(LocalHook.GetProcAddress("user32.dll", "CreateWindowExW"), new CreateWindowExDelegate(CreateWindowExW_Hooked), this);
                        CreateWindowHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                        DestroyWindowHook = LocalHook.Create(LocalHook.GetProcAddress("user32.dll", "DestroyWindow"), new DestroyWindowDelegate(DestroyWindow_Hooked), this);
                        DestroyWindowHook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                        break;
                    case Program.Func0:
                        Func0Hook = LocalHook.Create(LocalHook.GetProcAddress("UnmanagedWithExports.exe", "Func0"), new Func0Delegate(Func0_Hooked), this);
                        Func0Hook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                        break;
                    case Program.Func1:
                        Func1Hook = LocalHook.Create(LocalHook.GetProcAddress("UnmanagedWithExports.exe", "Func1"), new Func1Delegate(Func1_Hooked), this);
                        Func1Hook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                        break;
                    case Program.Func4:
                        Func4Hook = LocalHook.Create(LocalHook.GetProcAddress("UnmanagedWithExports.exe", "Func4"), new Func4Delegate(Func4_Hooked), this);
                        Func4Hook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                        break;
                    case Program.Func8:
                        Func8Hook = LocalHook.Create(LocalHook.GetProcAddress("UnmanagedWithExports.exe", "Func8"), new Func8Delegate(Func8_Hooked), this);
                        Func8Hook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                        break;
                    case Program.Func9:
                        Func9Hook = LocalHook.Create(LocalHook.GetProcAddress("UnmanagedWithExports.exe", "Func9"), new Func9Delegate(Func9_Hooked), this);
                        Func9Hook.ThreadACL.SetExclusiveACL(new int[] { 0 });
                        Func9Hook.Dispose();
                        break;
                    default:
                        break;
                }

            }
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        unsafe delegate int Func9Delegate(int* a, int* b, int* c, int* d, int* e, int* f, int* g, int* h, int *i);

        [DllImport("UnmanagedWithExports.exe", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        unsafe static extern int Func9(int* a, int* b, int* c, int* d, int* e, int* f, int* g, int* h, int* i);

        unsafe static int Func9_Hooked(int* a, int* b, int* c, int* d, int* e, int* f, int* g, int* h, int *i)
        {
            IntPtr backup = IntPtr.Zero;
                
            Console.WriteLine("Func9 Hook: a=0x{0:X}, b=0x{1:X} c=0x{2:X} d=0x{3:X} e=0x{4:X} f=0x{5:X} g=0x{6:X} h=0x{7:X}, i=0x{8:X}", *a, *b, *c, *d, *e, *f, *g, *h, *i);
            int lret = Func9(a, b, c, d, e, f, g, h, i);
            Console.WriteLine("Func9 Hook: a=0x{0:X}, b=0x{1:X} c=0x{2:X} d=0x{3:X} e=0x{4:X} f=0x{5:X} g=0x{6:X} h=0x{7:X}, i=0x{8:X}, lret = {9}, address: {10:X}", *a, *b, *c, *d, *e, *f, *g, *h, *i, lret, backup.ToInt64());
            try
            {

                NativeAPI.LhBarrierBeginStackTrace(out backup);

                Console.WriteLine("After patching orig address was: {0:X}", backup.ToInt64());

       //         Debugger.Break();


            }
            finally
            {
                NativeAPI.LhBarrierEndStackTrace(backup);
                Console.WriteLine("Did patch back again");
         //       Debugger.Break();


            }
            return 0;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        unsafe delegate int Func8Delegate(int* a, int* b, int* c, int* d, int* e, int* f, int* g, int* h);

        [DllImport("UnmanagedWithExports.exe", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        unsafe static extern int Func8(int* a, int* b, int* c, int* d, int* e, int* f, int* g, int* h);

        unsafe static int Func8_Hooked(int* a, int* b, int* c, int* d, int* e, int* f, int* g, int* h)
        {
            Console.WriteLine("Func8 Hook: a=0x{0:X}, b=0x{1:X} c=0x{2:X} d=0x{3:X} e=0x{4:X} f=0x{5:X} g=0x{6:X} h=0x{7:X}", *a, *b, *c, *d, *e, *f, *g, *h);
            int lret = Func8(a, b, c, d, e, f, g, h);
            Console.WriteLine("Func8 Hook: a=0x{0:X}, b=0x{1:X} c=0x{2:X} d=0x{3:X} e=0x{4:X} f=0x{5:X} g=0x{6:X} h=0x{7:X}, lret = {8}", *a, *b, *c, *d, *e, *f, *g, *h, lret);
            return 0;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        unsafe delegate int Func4Delegate(int* a, int* b, int* c, int* d);

        [DllImport("UnmanagedWithExports.exe", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        unsafe static extern int Func4(int* a, int* b, int* c, int* d);

        unsafe static int Func4_Hooked(int* a, int* b, int* c, int* d)
        {
            Console.WriteLine("Func4 Hook: a=0x{0:X}, b=0x{1:X} c=0x{2:X} d=0x{3:X}", *a, *b, *c, *d);
            int lret = Func4(a, b, c, d);
            Console.WriteLine("Func4 Hook: a=0x{0:X}, b=0x{1:X} c=0x{2:X} d=0x{3:X} lret = {4}", *a, *b, *c, *d, lret);
            return 0;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        unsafe delegate int Func1Delegate(int* a);

        [DllImport("UnmanagedWithExports.exe", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        unsafe static extern int Func1(int* a);

        unsafe static int Func1_Hooked(int* a)
        {
            Console.WriteLine("Func1 Hook: a=0x{0:X}", *a);
            int lret = Func1(a);
            Console.WriteLine("Func1 Hook: a=0x{0:X}, lret = {1}", *a, lret);
            return 0;
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        unsafe delegate int Func0Delegate();

        [DllImport("UnmanagedWithExports.exe", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        unsafe static extern int Func0();

        unsafe static int Func0_Hooked()
        {
            Console.WriteLine("Func0 Hook");
            int lret = Func0();
            Console.WriteLine("Func0 Hook returned {0}", lret);
            return 0;
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet = CharSet.Unicode,SetLastError = true)]
        delegate IntPtr DCreateFile(String InFileName, UInt32 InDesiredAccess, UInt32 InShareMode, IntPtr InSecurityAttributes, 
                                    UInt32 InCreationDisposition, UInt32 InFlagsAndAttributes, IntPtr InTemplateFile);

        // just use a P-Invoke implementation to get native API access from C# (this step is not necessary for C++.NET)
        [DllImport("kernel32.dll",CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr CreateFile(String InFileName, UInt32 InDesiredAccess, UInt32 InShareMode, IntPtr InSecurityAttributes,
                                        UInt32 InCreationDisposition, UInt32 InFlagsAndAttributes, IntPtr InTemplateFile);

        // this is where we are intercepting all file accesses!
        static IntPtr CreateFile_Hooked(String InFileName, UInt32 InDesiredAccess, UInt32 InShareMode, IntPtr InSecurityAttributes,
                                        UInt32 InCreationDisposition, UInt32 InFlagsAndAttributes, IntPtr InTemplateFile)
        {

            IntPtr lret = IntPtr.Zero;
            try
            {
                // To record traces you need to install the Windows Performance Toolkit which is part of the Windows 8.1 SDK
                // xperf -on base 
                lret = CreateFile( InFileName, InDesiredAccess, InShareMode, InSecurityAttributes, 
                                   InCreationDisposition, InFlagsAndAttributes, InTemplateFile);

                IntPtr backup = IntPtr.Zero;

                try
                {
                    NativeAPI.LhBarrierBeginStackTrace(out backup);
                    TestProvider.EventWriteCreateFile(InFileName, (ulong)lret.ToInt64());
                    TestProvider.EventWriteAllocateHandle((ulong)lret.ToInt64(), 1, "CreateFile");
                }
                finally
                {
                    NativeAPI.LhBarrierEndStackTrace(backup);
                }
            }
            catch
            {
            }

            // call original API...
            return lret;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WNDCLASS
        {
            public uint style;
            public IntPtr lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpszMenuName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string lpszClassName;
        }

        [DllImport("user32.dll", SetLastError = true)]
        static extern System.UInt16 RegisterClassW([In] ref WNDCLASS lpWndClass);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr CreateWindowExDelegate(UInt32 dwExStyle, IntPtr lpClassName, IntPtr lpWindowName,
                                               UInt32 dwStyle, Int32 x, Int32 y, Int32 nWidth, Int32 nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr CreateWindowExW( UInt32 dwExStyle, IntPtr lpClassName, IntPtr lpWindowName,
                                              UInt32 dwStyle, Int32 x, Int32 y, Int32 nWidth, Int32 nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

        static IntPtr CreateWindowExW_Hooked(UInt32 dwExStyle, IntPtr lpClassName, IntPtr lpWindowName,
                                             UInt32 dwStyle, Int32 x, Int32 y, Int32 nWidth, Int32 nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam)
        {
            IntPtr lret = IntPtr.Zero;
            lret = CreateWindowExW(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
            IntPtr backup = IntPtr.Zero;
            try
            {
                NativeAPI.LhBarrierBeginStackTrace(out backup);

                TestProvider.EventWriteAllocateHandle((ulong)lret.ToInt64(), 1, "CreateWindowExW");
            }
            finally
            {
                NativeAPI.LhBarrierEndStackTrace(backup);
            }
            return lret;
        }

        [DllImport("user32.dll", SetLastError = true)]
        static extern System.IntPtr DefWindowProcW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool DestroyWindowDelegate(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DestroyWindow(IntPtr hWnd);

        static bool DestroyWindow_Hooked(IntPtr hWnd)
        {
            bool lret = DestroyWindow(hWnd);
            TestProvider.EventWriteFreeHandle((ulong)hWnd.ToInt64(), -1, "DestroyWindow");
            return lret;
        }
    }
}
