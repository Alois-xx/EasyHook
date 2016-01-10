using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ETWStackwalk
{
    public class InterprocessInterface : MarshalByRefObject
    {
        public void IsInstalled(Int32 InClientPID)
        {
            Console.WriteLine("ETWStackwalk has been installed in target {0}.\r\n", InClientPID);
        }

        public void OnCreateFile(Int32 InClientPID, String[] InFileNames)
        {
            for (int i = 0; i < InFileNames.Length; i++)
            {
                Console.WriteLine(InFileNames[i]);
            }
        }

        public void ReportException(Exception InInfo)
        {
            Console.WriteLine("The target process has reported an error:\r\n" + InInfo.ToString());
        }

        public void Ping()
        {
        }
    }
}
