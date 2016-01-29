using System;
using System.Collections.Generic;
using System.Runtime.Remoting;
using System.Text;
using System.IO;
using EasyHook;
using System.Windows.Forms;
using System.Linq;
using System.Diagnostics;
using System.GACManagedAccess;
using System.Threading.Tasks;
using System.Threading;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ETWStackwalk
{
    class Program
    {
        static readonly string Help = "ETWStackWalk.exe v" + GetVersion() + " by Alois Kraus 2015" + Environment.NewLine +
                               "Injects an ETW tracer to external processes to find resource leaks. Works for x64 since Win 8 or later. Works for 32 bit processes since Windows 7." + Environment.NewLine +
                               "ETWStackWalk [-hook [createfile] [createwindow] [funcx]] [-debug] [-help] [-pid ddd] [-start executable with optionalargs]" + Environment.NewLine +
                               "   -help                 This message" + Environment.NewLine +
                               "   -hook                 Hook specified methods to trace handle leaks (funcx methods are hooked for unit testing in conjunction with UnmangedHook.exe)." + Environment.NewLine +
                               "   -pid ddd              Hook into specified process" + Environment.NewLine +
                               "   -start executable     Start executable and then hook after 5s to give it time to initialize." + Environment.NewLine +
                               "   -noetw                Disable ETW recording (used for unit testing)." + Environment.NewLine +
                               "   -debug                Used to debug EasyHook trampoline code. Hook notepad.exe and start Windbg of Windows 10 SDK." + Environment.NewLine +
                               "Examples: " + Environment.NewLine +
                               "Monitor all CreateWindow/DestroyWind calls to detect window handle leaks in an already running application with process id ddd" + Environment.NewLine +
                               " ETWStackWalk.exe -hook createwindow -pid dddd" + Environment.NewLine +
                               "Monitor all CreateFile calls. There you can log e.g. return code, passed file name, flags and other flags of interest." + Environment.NewLine +
                               " ETWStackWalk.exe -hook createfile -pid dddd" + Environment.NewLine +
                               "Test hooking a method which writes if hooked an ETW event for every allocation and deallcation event to simulate a handle leak." + Environment.NewLine +
                               " ETWStackWalk.exe -hook funcetw -start UnmanagedWithExports.exe 500000" + Environment.NewLine +
                               "If something goes wrong you can directly debug it with Windbg if you have the Win10 SDK installed by adding the -debug switch" + Environment.NewLine +
                               " ETWStackWalk.exe -hook funcetw -debug -start UnmanagedWithExports.exe 500000" + Environment.NewLine +
                               "To check for stack corruptions caused by changes to EasyHook you can hook method with a different set of method arguments" + Environment.NewLine +
                               " ETWStackWalk.exe -hook func0 func1 func4 func8 func9 -start UnmanagedWithExports.exe 0" + Environment.NewLine;

        static String ChannelName = null;

        enum ProgramAction
        {
            None,
            Debug,
            Hook,
            Help,
        }

        ProgramAction Action;

        List<string> HookMethods = new List<string>();

        public const string CreateFileHookName = "createfile";
        public const string CreateWindowHookName = "createwindow";
        // Used for unit testing in conjunction with UnmanagedHook.exe to check for stack corruptions
        // when a varying number of stack parameters are passed.
        public const string Func0 = "func0";
        public const string Func1 = "func1";
        public const string Func4 = "func4";
        public const string Func8 = "func8";
        public const string Func9 = "func9";
        public const string FuncETW = "funcetw";

        int Pid = -1;
        bool ETWRecording = true;
        List<string> ExeArgs;
        string ExeName;

        public Program(string[] args)
        {
            ParseArgs(args);
        }

        private void ParseArgs(string[] args)
        {
            var argQueue = new Queue<string>(args.Select(x=>x.ToLower()));

            while(argQueue.Count>0)
            {
                string currentArg = argQueue.Dequeue();
                switch(currentArg)
                {
                    case "-debug":
                        Action = ProgramAction.Debug;
                        break;
                    case "-pid":
                        var pid = GetArgParameters(argQueue);
                        if( pid.Count != 1 || (pid.Count==1 && !pid[0].All(Char.IsDigit)))
                        {
                            throw new NotSupportedException(String.Format("Expected one pid parameter but got instead only {0}: {1}", pid.Count, String.Join(" ", pid)));
                        }
                        Pid = int.Parse(pid[0]);
                        break;
                    case "-hook":
                        HookMethods = GetArgParameters(argQueue);
                        if(HookMethods.Count == 0)
                        {
                            throw new NotSupportedException("Command line argument -hook expects additional arguments.");
                        }
                        Action = ProgramAction.Hook;
                        break;
                    case "-start":
                        ExeArgs = new List<string>();
                        while(argQueue.Count > 0 ) // all other paramters belong to the executable
                        {
                            ExeArgs.Add(argQueue.Dequeue());
                        }
                        if( ExeArgs.Count == 0)
                        {
                            throw new NotSupportedException("No exectuable name given to -start argument!");
                        }
                        ExeName = ExeArgs[0];
                        ExeArgs.RemoveAt(0);
                        break;
                    case "-noetw":
                        ETWRecording = false;
                        break;
                    case "-?":
                    case "-help":
                        Action = ProgramAction.Help;
                        break;
                    default:
                        throw new NotSupportedException(String.Format("The command line argument: {0} is not supported", currentArg));
                }
            }
        }

        private List<string> GetArgParameters(Queue<string> argQueue)
        {
            List<string> lret = new List<string>();
            while(argQueue.Count > 0)
            {
                var possibleParam = argQueue.Peek();
                if( possibleParam.StartsWith("-")) // no parameter but other argument
                {
                    break;
                }
                else
                {
                    lret.Add(argQueue.Dequeue());
                }
            }

            return lret;
        }

        static void Main(string[] args)
        {
            try
            {
                new Program(args).Run();
            }
            catch(Exception ex)
            {
                PrintHelp();
                Console.WriteLine("Error: {0}: {1}", ex.GetType().Name, ex.Message);
            }
        }

        private void Run()
        {
            switch(Action)
            {
                case ProgramAction.Debug:
                    StartWindbgInHookedProcess();
                    break;
                case ProgramAction.Help:
                case ProgramAction.None:
                    PrintHelp();
                    break;
                case ProgramAction.Hook:
                    HookAndStartStopETW(HookMethods);
                    break;
                default:
                    PrintHelp();
                    break;
            }
        }


        void HookAndStartStopETW(List<string> hookMethods)
        {
            if (ETWRecording)
            {
                StartETWRecording();
            }

            Hook(hookMethods);

            Console.WriteLine("Press Enter to stop recording");
            Console.ReadLine();

            if (ETWRecording)
            {
                StopETWRecording();
            }
        }

        private void Hook(List<string> hookMethods)
        {
            if( Pid == -1 )
            {
                using (Process p = Process.Start(ExeName, String.Join(" ", ExeArgs)))
                {
                    Pid = p.Id;
                }
                Thread.Sleep(2000);
            }
            Console.WriteLine("Hooking into proces {0} for {1}", Pid, String.Join(" ", hookMethods));

            try
            {
                RemoteHooking.IpcCreateServer<InterprocessInterface>(ref ChannelName, WellKnownObjectMode.SingleCall);

                string currentExeName = Process.GetCurrentProcess().MainModule.FileName;

                RemoteHooking.Inject(
                    Pid,
                    InjectionOptions.DoNotRequireStrongName,
                    currentExeName,
                    currentExeName,
                    ChannelName,
                    hookMethods);

            }
            catch (Exception ExtInfo)
            {
                Console.WriteLine("There was an error while connecting to target:\r\n{0}", ExtInfo.ToString());
            }
         
        }

        private static void PrintHelp()
        {
            Console.WriteLine(Help);
        }

        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWow64Process([In] IntPtr processHandle,[Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        private void StartWindbgInHookedProcess()
        {
            ETWRecording = false;
            
            
            if( Pid == -1 && String.IsNullOrEmpty(ExeName) )
            {
                ExeName = "notepad.exe";
            }

            if( HookMethods.Count == 0 )
            {
                HookMethods.Add(CreateFileHookName);
            }

            Hook(HookMethods);
            Thread.Sleep(1000);
            bool is32Bit;
            IsWow64Process(Process.GetProcessById(Pid).Handle, out is32Bit);
            if (is32Bit)
            {
                Process.Start(@"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe", String.Format("-p {0} -c \".symfix;.reload;sxe clr;g\"", Pid));
            }
            else
            {
                string Location1 = @"C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe";
                string Location2 = @"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe";
                string debuggerPath = null;
                if( File.Exists(Location1))
                {
                    debuggerPath = Location1;
                }
                else if( File.Exists(Location2))
                {
                    debuggerPath = Location2;
                }
                Process.Start(debuggerPath, String.Format("-p {0} -c \".symfix;.reload;g\"", Pid));
            }

            Console.WriteLine("Press enter to stop");
            Console.ReadLine();
        }

         private static void StartETWRecording()
        {
            Console.WriteLine("Start ETW Recording. You need the Windows Performance Toolkit installed (preferably from Windows 10 SDK).");

            // wpr.exe -start GeneralProfile -start TestProvider.wprp
            // Start ETW Recording
            ProcessStartInfo info = new ProcessStartInfo("wpr.exe", "-start GeneralProfile -start TestProvider.wprp")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false
            };

            var p = Process.Start(info);
            Console.WriteLine("WPR Output: {0}", p.StandardOutput.ReadToEnd());
            p.WaitForExit();
        }

        private static void StopETWRecording()
        {
            Console.WriteLine("Stop ETW Recording and save data to {0}", Environment.ExpandEnvironmentVariables(@"%temp%\CreateFileLogs.etl"));
            Console.WriteLine("Open the file with WPA.exe and add Generic Events to your view. There TestProvider with the CreateFile Events should show up.");
            Console.WriteLine("Right click on the Generic Events columns to bring up the context menu. Select Open View Editor. Add the Stack field to your column selection and load the symbols.");

            // wpr -stop c:\temp\createfile.etl
            var stopInfo = new ProcessStartInfo("wpr.exe", String.Format("-stop {0}", Environment.ExpandEnvironmentVariables(@"%temp%\CreateFileLogs.etl")))
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            var stopRecording = Process.Start(stopInfo);
            Task<string> stderrTask = Task.Factory.StartNew(() => stopRecording.StandardError.ReadToEnd());
            Console.WriteLine("Stop WPR Output: {0}", stopRecording.StandardOutput.ReadToEnd());
            stderrTask.Wait();
            if( !String.IsNullOrEmpty(stderrTask.Result) )
            {
                Console.WriteLine("WPR Error: {0}", stderrTask.Result);
            }
            stopRecording.WaitForExit();
        }

        static string GetVersion()
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            return String.Format("{0}.{1}.{2}.{3}", version.Major, version.Minor, version.Revision, version.Build);
        }
    }
}