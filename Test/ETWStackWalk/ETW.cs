//---------------------------------------------------------------------
// <autogenerated>
//
//     Generated by Message Compiler (mc.exe)
//
//     Copyright (c) Microsoft Corporation. All Rights Reserved.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </autogenerated>
//---------------------------------------------------------------------




namespace ETWStackwalk
{
using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.Diagnostics.Eventing;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Security.Principal;

    public static class TestProvider
    {
        //
        // Provider TestProvider Event Count 3
        //

        internal static EventProviderVersionTwo m_provider = new EventProviderVersionTwo(new Guid("c0899b1a-6345-4e8f-9b6b-13e44a7ed5ba"));
        //
        // Task :  eventGUIDs
        //
        private static Guid AcquireId = new Guid("ad14e1b1-04f6-480b-964a-4182f41a98ce");
        private static Guid ReleaseId = new Guid("8ad0f072-f6d8-4db1-8ade-b892b574d2b5");

        //
        // Event Descriptors
        //
        private static EventDescriptor CreateFile;
        private static EventDescriptor AcquireResource;
        private static EventDescriptor ReleaseResource;


        static TestProvider()
        {
            unchecked
            {
                CreateFile = new EventDescriptor(0x0, 0x1, 0x0, 0x4, 0x0, 0x0, (long)0x0);
                AcquireResource = new EventDescriptor(0x1, 0x1, 0x0, 0x4, 0x1, 0x1, (long)0x0);
                ReleaseResource = new EventDescriptor(0x2, 0x1, 0x0, 0x4, 0x2, 0x2, (long)0x0);
            }
        }


        //
        // Event method for CreateFile
        //
        public static bool EventWriteCreateFile(string FileName, ulong ReturnCode)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateCreateFileTemplate(ref CreateFile, FileName, ReturnCode);
        }

        //
        // Event method for AcquireResource
        //
        public static bool EventWriteAcquireResource(ulong Handle, long AllocSize, string Allocator)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateResourceDefinition(ref AcquireResource, Handle, AllocSize, Allocator);
        }

        //
        // Event method for ReleaseResource
        //
        public static bool EventWriteReleaseResource(ulong Handle, long AllocSize, string Allocator)
        {

            if (!m_provider.IsEnabled())
            {
                return true;
            }

            return m_provider.TemplateResourceDefinition(ref ReleaseResource, Handle, AllocSize, Allocator);
        }
    }

    internal class EventProviderVersionTwo : EventProvider
    {
         internal EventProviderVersionTwo(Guid id)
                : base(id)
         {}


        [StructLayout(LayoutKind.Explicit, Size = 16)]
        private struct EventData
        {
            [FieldOffset(0)]
            internal UInt64 DataPointer;
            [FieldOffset(8)]
            internal uint Size;
            [FieldOffset(12)]
            internal int Reserved;
        }



        internal unsafe bool TemplateCreateFileTemplate(
            ref EventDescriptor eventDescriptor,
            string FileName,
            ulong ReturnCode
            )
        {
            int argumentCount = 2;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].Size = (uint)(FileName.Length + 1)*sizeof(char);

                userDataPtr[1].DataPointer = (UInt64)(&ReturnCode);
                userDataPtr[1].Size = (uint)(sizeof(long)  );

                fixed (char* a0 = FileName)
                {
                    userDataPtr[0].DataPointer = (ulong)a0;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }



        internal unsafe bool TemplateResourceDefinition(
            ref EventDescriptor eventDescriptor,
            ulong Handle,
            long AllocSize,
            string Allocator
            )
        {
            int argumentCount = 3;
            bool status = true;

            if (IsEnabled(eventDescriptor.Level, eventDescriptor.Keywords))
            {
                byte* userData = stackalloc byte[sizeof(EventData) * argumentCount];
                EventData* userDataPtr = (EventData*)userData;

                userDataPtr[0].DataPointer = (UInt64)(&Handle);
                userDataPtr[0].Size = (uint)(sizeof(long)  );

                userDataPtr[1].DataPointer = (UInt64)(&AllocSize);
                userDataPtr[1].Size = (uint)(sizeof(long)  );

                userDataPtr[2].Size = (uint)(Allocator.Length + 1)*sizeof(char);

                fixed (char* a0 = Allocator)
                {
                    userDataPtr[2].DataPointer = (ulong)a0;
                    status = WriteEvent(ref eventDescriptor, argumentCount, (IntPtr)(userData));
                }
            }

            return status;

        }

    }

}
