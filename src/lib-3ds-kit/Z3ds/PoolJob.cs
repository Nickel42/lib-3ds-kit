using System.Runtime.ExceptionServices;

namespace Lib3dsKit.Z3ds;

/// <summary>
/// A piece of work queued to the thread pool that the thread waiting for it runs itself if no pool thread
/// has started it yet. Callers often run on the pool themselves, so waiting never depends on a free pool thread.
/// </summary>
internal sealed class PoolJob<T>
{
    private readonly Func<T> _work;
    private readonly ManualResetEventSlim _done = new(false);
    private int _claimed;
    private T? _result;
    private ExceptionDispatchInfo? _error;

    public PoolJob(Func<T> work)
    {
        _work = work;
        ThreadPool.UnsafeQueueUserWorkItem(static job => job.TryRun(), this, preferLocal: false);
    }

    /// <summary>The result, once the work is done (here, if no pool thread had started it). Rethrows its exception.</summary>
    public T Wait()
    {
        if (!TryRun()) _done.Wait();
        _error?.Throw();
        return _result!;
    }

    private bool TryRun()
    {
        if (Interlocked.Exchange(ref _claimed, 1) != 0) return false;
        try { _result = _work(); }
        catch (Exception ex) { _error = ExceptionDispatchInfo.Capture(ex); }
        finally { _done.Set(); }
        return true;
    }
}
