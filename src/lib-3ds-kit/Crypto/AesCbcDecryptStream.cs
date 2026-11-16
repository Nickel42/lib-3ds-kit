using System.Buffers;
using System.Security.Cryptography;
using Lib3dsKit.IO;

namespace Lib3dsKit.Crypto;

/// <summary>
/// Random-access AES-128-CBC decryption view over a ciphertext stream
/// (no padding; the ciphertext length must be a multiple of 16).
/// Plaintext block i = AES-Decrypt(C[i]) XOR C[i-1] (C[-1] = IV), so any range can be
/// decrypted by also reading the block before it.
/// </summary>
public sealed class AesCbcDecryptStream : VirtualStream
{
    private readonly Stream _cipher;
    private readonly byte[] _iv;
    private readonly Aes _aes;
    // The last ciphertext block of the previous read: the IV of a read that carries on from it.
    private readonly byte[] _nextIv = new byte[16];
    private long _nextIvAt = -1;

    public AesCbcDecryptStream(Stream ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (ciphertext.Length % 16 != 0)
            throw new ArgumentException("CBC ciphertext length must be a multiple of 16.", nameof(ciphertext));
        _cipher = ciphertext;
        _iv = iv.ToArray();
        _aes = Aes.Create();
        _aes.Key = key.ToArray();
    }

    public override long Length => _cipher.Length;

    protected override void ReadAt(long position, Span<byte> buffer)
    {
        long start = position & ~15L;
        long end = (position + buffer.Length + 15) & ~15L;
        int span = (int)(end - start);
        Span<byte> iv = stackalloc byte[16];
        if (start == 0) _iv.CopyTo(iv);
        else if (start == _nextIvAt) _nextIv.CopyTo(iv);
        else ReadExactlyAt(_cipher, start - 16, iv);
        _nextIvAt = -1;

        if (position == start && span == buffer.Length)
        {
            // Block-aligned (as sequential copies are): decrypt in place in the caller's buffer.
            ReadExactlyAt(_cipher, start, buffer);
            buffer[^16..].CopyTo(_nextIv);
            _aes.DecryptCbc(buffer, iv, buffer, PaddingMode.None);
            _nextIvAt = end;
            return;
        }

        byte[] ct = ArrayPool<byte>.Shared.Rent(span);
        byte[] pt = ArrayPool<byte>.Shared.Rent(span);
        try
        {
            ReadExactlyAt(_cipher, start, ct.AsSpan(0, span));
            ct.AsSpan(span - 16, 16).CopyTo(_nextIv);
            _nextIvAt = end;
            _aes.DecryptCbc(ct.AsSpan(0, span), iv, pt.AsSpan(0, span), PaddingMode.None);
            pt.AsSpan((int)(position - start), buffer.Length).CopyTo(buffer);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(ct);
            ArrayPool<byte>.Shared.Return(pt);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _aes.Dispose();
        base.Dispose(disposing);
    }
}
