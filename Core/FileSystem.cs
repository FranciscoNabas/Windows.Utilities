using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

namespace Windows.Utilities.FileSystem
{
    internal partial class NativeFunctions
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateDirectoryW(
            string lpPathName,
            [In, Optional] IntPtr lpSecurityAttributes
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CopyFileEx(
            string lpExistingFileName,
            string lpNewFileName,
            Path.CopyProgressRoutine lpProgressRoutine,
            IntPtr lpData,
            ref bool pbCancel,
            uint dwCopyFlags
        );
    }

    public class Path
    {
        internal delegate uint CopyProgressRoutine(
            long TotalFileSize,
            long TotalBytesTransferred,
            long StreamSize,
            long StreamBytesTransferred,
            uint dwStreamNumber,
            uint dwCallbackReason,
            IntPtr hSourceFile,
            IntPtr hDestinationFile,
            IntPtr lpData
        );

        public static string GetpathCommonRoot(HashSet<string> path_list)
        {
            var MatchingChars =
                from len in Enumerable.Range(0, path_list.Min(s => s.Length)).Reverse()
                let possibleMatch = path_list.First().Substring(0, len)
                where path_list.All(f => f.StartsWith(possibleMatch))
                select possibleMatch;

            return System.IO.Path.GetDirectoryName(MatchingChars.First());
        }
    }

    public class Smb
    {
        private readonly string _path;
        private readonly string _file_name;
        private readonly NetworkCredential? _credential;

        public Smb(string path) => (_path, _file_name) = (path, System.IO.Path.GetFileName(path));
        public Smb(string path, NetworkCredential credential) =>
            (_path, _credential, _file_name) = (path, credential, System.IO.Path.GetFileName(path));

        public void Copy(string destination, bool force = false)
        {
            if (_credential is not null)
            {
                string destination_full_name = System.IO.Path.Combine(destination, _file_name);
                NETRESOURCE resource_info = new()
                {
                    dwScope = NETWORK_RESOURCE_SCOPE.RESOURCE_GLOBALNET,
                    dwType = NETWORK_RESOURCE_TYPE.RESOURCETYPE_DISK,
                    dwDisplayType = NETWORK_RESOURCE_DISPLAY_TYPE.RESOURCEDISPLAYTYPE_SHARE,
                    lpRemoteName = System.IO.Path.GetDirectoryName(_path)
                };
                using NetworkConnection connection = new(_path, _credential);
                connection.Connect(resource_info);
                System.IO.File.Copy(_path, destination_full_name, force);
            }
            else
            {
                string destination_full_name = System.IO.Path.Combine(destination, _file_name);
                NETRESOURCE resource_info = new()
                {
                    dwScope = NETWORK_RESOURCE_SCOPE.RESOURCE_GLOBALNET,
                    dwType = NETWORK_RESOURCE_TYPE.RESOURCETYPE_DISK,
                    dwDisplayType = NETWORK_RESOURCE_DISPLAY_TYPE.RESOURCEDISPLAYTYPE_SHARE,
                    lpRemoteName = System.IO.Path.GetDirectoryName(_path)
                };
                using NetworkConnection connection = new(_path);
                connection.Connect(resource_info);
                System.IO.File.Copy(_path, destination_full_name, force);
            }
        }
    }
}
