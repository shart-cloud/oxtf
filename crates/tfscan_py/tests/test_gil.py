import threading
import time

import tfscan


def progress_during_scan(d, release):
    """(spinner rate during the scan / idle baseline rate, scan seconds)."""

    count = 0
    stop = False

    def spin():
        nonlocal count
        while not stop:
            count += 1

    t = threading.Thread(target=spin)
    t.start()
    try:
        time.sleep(0.05)
        c0, t0 = count, time.perf_counter()
        time.sleep(0.3)  # baseline: main thread idle (GIL free)
        base_rate = (count - c0) / (time.perf_counter() - t0)
        c0, t0 = count, time.perf_counter()
        inner, _ = tfscan._tfscan.scan([str(d)], recursive=True, threads=1, _release_gil=release)
        dt = time.perf_counter() - t0
        scan_rate = (count - c0) / dt
    finally:
        stop = True
        t.join()
    assert inner.stats["roots"] == 3000
    return scan_rate / base_rate, dt


def test_scan_releases_gil(generated):
    """A Python thread keeps running while a scan executes in Rust; with the
    GIL held (test-only control) it does not."""
    d = generated(3000, 11)
    tfscan.scan(d, recursive=True, threads=1)  # warm the page cache
    released, dt = progress_during_scan(d, True)
    held, dt_held = progress_during_scan(d, False)
    print(f"spinner progress vs idle: GIL released {released:.2f} ({dt:.3f} s scan), "
          f"GIL held {held:.3f} ({dt_held:.3f} s scan)")
    assert dt > 0.1 and dt_held > 0.1
    # Holding the GIL for the whole scan leaves the spinner at most about one
    # switch interval (5 ms) of progress.
    assert held < 0.1
    assert released > 0.25
