using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace Sentinella.Core;

internal static class NativeFiles
{
    private const uint GenericRead = 0x80000000, Delete = 0x00010000;
    private const uint OpenExisting = 3, OpenReparsePoint = 0x00200000, SequentialScan = 0x08000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct FileInfo
    {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint sharing,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInfo info);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,
        StringBuilder result, uint count, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle,
        int infoClass, ref int deleteFile, uint size);

    internal static string NormalizeLocal(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (path.StartsWith(@"\\", StringComparison.Ordinal) || path.IndexOf(':', Math.Min(2, path.Length)) >= 0)
            throw new IOException("Percorsi di rete, dispositivi e alternate data stream non supportati.");
        string full = Path.GetFullPath(path);
        if (full.StartsWith(@"\\", StringComparison.Ordinal) ||
            new DriveInfo(Path.GetPathRoot(full)!).DriveType == DriveType.Network)
            throw new IOException("È richiesto un disco locale.");
        return full;
    }

    internal static void RejectReparseAncestors(string path)
    {
        string? current = path;
        while (!string.IsNullOrEmpty(current))
        {
            if ((File.Exists(current) || Directory.Exists(current)) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Collegamenti e reparse point non supportati: " + current);
            current = Path.GetDirectoryName(current);
        }
    }

    internal static FileStream OpenStable(string path, bool allowDelete, bool rejectHardLinks)
    {
        RejectReparseAncestors(path);
        var handle = CreateFileW(path, GenericRead | (allowDelete ? Delete : 0),
            0, IntPtr.Zero, OpenExisting, OpenReparsePoint | SequentialScan, IntPtr.Zero);
        try
        {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!GetFileInformationByHandle(handle, out var info))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((info.Attributes & (uint)(FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                throw new IOException("Il file è una directory o un collegamento.");
            if (rejectHardLinks && info.Links != 1)
                throw new IOException("File con hard link non ammessi in quarantena.");
            var final = new StringBuilder(32768);
            uint count = GetFinalPathNameByHandleW(handle, final, (uint)final.Capacity, 0);
            if (count == 0 || count >= final.Capacity) throw new IOException("Percorso finale non verificabile.");
            string actual = final.ToString();
            if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual[4..];
            if (!string.Equals(actual, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase))
                throw new IOException("Il percorso del file è cambiato o contiene un alias.");
            return new FileStream(handle, FileAccess.Read);
        }
        catch { handle.Dispose(); throw; }
    }

    internal static void AssertHandlePath(SafeFileHandle handle, string expected)
    {
        var final = new StringBuilder(32768);
        uint count = GetFinalPathNameByHandleW(handle, final, (uint)final.Capacity, 0);
        if (count == 0 || count >= final.Capacity) throw new IOException("Percorso finale non verificabile.");
        string actual = final.ToString();
        if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual[4..];
        if (!string.Equals(actual, Path.GetFullPath(expected), StringComparison.OrdinalIgnoreCase))
            throw new IOException("Percorso finale differente dal percorso richiesto.");
    }
    internal static void DeleteOnClose(FileStream stream)
    {
        int flag = 1;
        if (!SetFileInformationByHandle(stream.SafeFileHandle, 4, ref flag, 4))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "Copia cifrata salvata; eliminazione originale non riuscita.");
    }
}

