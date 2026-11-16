using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Lib3dsKit.IO;

namespace Lib3dsKit.Crypto;

/// <summary>
/// AES-128-CTR with a 128-bit big-endian counter, built on AES-ECB (.NET has no CTR mode).
/// Random access: any byte range can be transformed independently.
/// Encryption and decryption are the same operation.
/// </summary>
public sealed class AesCtrCipher : IDisposable
{
    private const int BatchBlocks = 4096; // 64 KiB of keystream per ECB call
    // Ranges this long are split across cores, in pieces this long (a multiple of the block size).
    internal const int ParallelThreshold = 1024 * 1024;
    private const int ParallelPiece = 256 * 1024;
    private readonly byte[] _key;
    private readonly Aes _aes;
    private readonly ConcurrentBag<Aes> _workers = new();

    public AesCtrCipher(ReadOnlySpan<byte> key)
    {
        if (key.Length != 16) throw new ArgumentException("AES-128 key must be 16 bytes.", nameof(key));
        _key = key.ToArray();
        _aes = Aes.Create();
        _aes.Key = _key;
    }

    /// <summary>
    /// XOR <paramref name="data"/> in place with the keystream, where <paramref name="data"/>[0]
    /// sits <paramref name="relativeOffset"/> bytes after the point where the counter equals
    /// <paramref name="counterBase"/>. A long range is worked on by several cores.
    /// </summary>
    public void Transform(UInt128 counterBase, long relativeOffset, Span<byte> data)
    {
        if (data.IsEmpty) return;
        ArgumentOutOfRangeException.ThrowIfNegative(relativeOffset);
        if (data.Length >= ParallelThreshold && Environment.ProcessorCount > 1)
            TransformParallel(counterBase, relativeOffset, data);
        else
            Transform(_aes, counterBase, relativeOffset, data);
    }

    /// <summary>
    /// Pieces of the keystream are made on the thread pool (CTR can start anywhere), each with its own
    /// <see cref="Aes"/>, and XORed into <paramref name="data"/> here, in order, as they come in.
    /// </summary>
    private void TransformParallel(UInt128 counterBase, long relativeOffset, Span<byte> data)
    {
        int length = data.Length;
        byte[] keystream = ArrayPool<byte>.Shared.Rent(length);
        var pieces = new PoolJob<bool>[(length + ParallelPiece - 1) / ParallelPiece];
        int waited = 0;
        try
        {
            for (int i = 0; i < pieces.Length; i++)
            {
                int start = i * ParallelPiece, n = Math.Min(ParallelPiece, length - start);
                pieces[i] = new PoolJob<bool>(() =>
                {
                    if (!_workers.TryTake(out var aes))
                    {
                        aes = Aes.Create();
                        aes.Key = _key;
                    }
                    try { Keystream(aes, counterBase, relativeOffset + start, keystream.AsSpan(start, n)); }
                    finally { _workers.Add(aes); }
                    return true;
                });
            }
            for (; waited < pieces.Length; waited++)
            {
                pieces[waited].Wait();
                int start = waited * ParallelPiece, n = Math.Min(ParallelPiece, length - start);
                Xor(data.Slice(start, n), keystream.AsSpan(start, n));
            }
        }
        finally
        {
            // After a failure, nothing may still be writing to the buffer when it goes back to the pool.
            for (; waited < pieces.Length; waited++)
                if (pieces[waited] is { } p) try { p.Wait(); } catch { }
            ArrayPool<byte>.Shared.Return(keystream);
        }
    }

    /// <summary>Writes the keystream itself into <paramref name="dest"/>.</summary>
    private static void Keystream(Aes aes, UInt128 counterBase, long relativeOffset, Span<byte> dest)
    {
        if ((relativeOffset & 15) != 0 || (dest.Length & 15) != 0)
        {
            dest.Clear();
            Transform(aes, counterBase, relativeOffset, dest);
            return;
        }
        // Block-aligned: AES-ECB of the counters is the keystream, written straight into place.
        UInt128 counter = counterBase + (UInt128)(ulong)(relativeOffset >> 4);
        int maxBlocks = Math.Min(BatchBlocks, dest.Length / 16);
        byte[] ctrBuf = ArrayPool<byte>.Shared.Rent(maxBlocks * 16);
        try
        {
            for (int done = 0; done < dest.Length;)
            {
                int blocks = Math.Min(maxBlocks, (dest.Length - done) / 16);
                for (int i = 0; i < blocks; i++)
                {
                    WriteCounter(ctrBuf.AsSpan(i * 16, 16), counter);
                    counter++;
                }
                aes.EncryptEcb(ctrBuf.AsSpan(0, blocks * 16), dest.Slice(done, blocks * 16), PaddingMode.None);
                done += blocks * 16;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ctrBuf);
        }
    }

    private static void Transform(Aes aes, UInt128 counterBase, long relativeOffset, Span<byte> data)
    {
        UInt128 counter = counterBase + (UInt128)(ulong)(relativeOffset >> 4);
        int skip = (int)(relativeOffset & 15);

        int maxBlocks = Math.Min(BatchBlocks, (skip + data.Length + 15) / 16);
        byte[] ctrBuf = ArrayPool<byte>.Shared.Rent(maxBlocks * 16);
        byte[] ksBuf = ArrayPool<byte>.Shared.Rent(maxBlocks * 16);
        try
        {
            int done = 0;
            while (done < data.Length)
            {
                int bytesWanted = skip + (data.Length - done);
                int blocks = Math.Min(maxBlocks, (bytesWanted + 15) / 16);
                for (int i = 0; i < blocks; i++)
                {
                    WriteCounter(ctrBuf.AsSpan(i * 16, 16), counter);
                    counter++;
                }
                var ks = ksBuf.AsSpan(0, blocks * 16);
                aes.EncryptEcb(ctrBuf.AsSpan(0, blocks * 16), ks, PaddingMode.None);
                int usable = Math.Min(blocks * 16 - skip, data.Length - done);
                Xor(data.Slice(done, usable), ks.Slice(skip, usable));
                done += usable;
                skip = 0;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ctrBuf);
            ArrayPool<byte>.Shared.Return(ksBuf);
        }
    }

    /// <summary>Big-endian 16-byte representation of a counter.</summary>
    public static void WriteCounter(Span<byte> dest, UInt128 value)
    {
        BinaryPrimitives.WriteUInt64BigEndian(dest, (ulong)(value >> 64));
        BinaryPrimitives.WriteUInt64BigEndian(dest[8..], (ulong)value);
    }

    public static UInt128 ReadCounter(ReadOnlySpan<byte> src) =>
        new(BinaryPrimitives.ReadUInt64BigEndian(src), BinaryPrimitives.ReadUInt64BigEndian(src[8..]));

    private static void Xor(Span<byte> data, ReadOnlySpan<byte> keystream)
    {
        if (keystream.Length < data.Length) throw new ArgumentException("Keystream too short.", nameof(keystream));
        ref byte d = ref MemoryMarshal.GetReference(data);
        ref byte k = ref MemoryMarshal.GetReference(keystream);
        nuint n = (nuint)data.Length, i = 0;
        // 128 bytes at a time, then 16, then the rest
        if (Vector256.IsHardwareAccelerated)
            for (; i + 128 <= n; i += 128)
            {
                (Vector256.LoadUnsafe(ref d, i) ^ Vector256.LoadUnsafe(ref k, i)).StoreUnsafe(ref d, i);
                (Vector256.LoadUnsafe(ref d, i + 32) ^ Vector256.LoadUnsafe(ref k, i + 32)).StoreUnsafe(ref d, i + 32);
                (Vector256.LoadUnsafe(ref d, i + 64) ^ Vector256.LoadUnsafe(ref k, i + 64)).StoreUnsafe(ref d, i + 64);
                (Vector256.LoadUnsafe(ref d, i + 96) ^ Vector256.LoadUnsafe(ref k, i + 96)).StoreUnsafe(ref d, i + 96);
            }
        for (; i + 16 <= n; i += 16)
            (Vector128.LoadUnsafe(ref d, i) ^ Vector128.LoadUnsafe(ref k, i)).StoreUnsafe(ref d, i);
        for (; i < n; i++)
            Unsafe.Add(ref d, (nint)i) ^= Unsafe.Add(ref k, (nint)i);
    }

    public void Dispose()
    {
        _aes.Dispose();
        while (_workers.TryTake(out var aes)) aes.Dispose();
    }
}

/// <summary>Helpers for one-shot AES operations on small buffers (title keys, tests).</summary>
public static class AesUtil
{
    public static byte[] CbcDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        return aes.DecryptCbc(data, iv, PaddingMode.None);
    }

    public static byte[] CbcEncrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data)
    {
        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        return aes.EncryptCbc(data, iv, PaddingMode.None);
    }
}
