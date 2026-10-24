"""Packet acquisition: live sniffing (scapy) and offline pcap replay.

Only IPv4 TCP/UDP packets are decoded; everything else is ignored, matching
the flow meter's scope.

scapy is imported lazily (and in full, as ``scapy.all``) so that every link
layer type - Ethernet, SLL, raw IP - is registered before a capture file is
read.
"""

from __future__ import annotations

import logging
import queue
from pathlib import Path
from typing import Callable, Optional

from .flowmeter import PROTO_TCP, PROTO_UDP, PacketRec

log = logging.getLogger("idsfw.capture")

_SCAPY = None


def scapy_all():
    """Imports (once) and returns the ``scapy.all`` module."""
    global _SCAPY
    if _SCAPY is None:
        import scapy.all as scapy_all_module  # noqa: PLC0415 - lazy import

        _SCAPY = scapy_all_module
    return _SCAPY


def decode_packet(pkt, ts: float | None = None) -> Optional[PacketRec]:
    """Converts a scapy packet into a :class:`PacketRec` (or None if not IPv4 TCP/UDP)."""
    scapy = scapy_all()
    ip = pkt.getlayer(scapy.IP)
    if ip is None:
        return None

    if pkt.haslayer(scapy.TCP):
        tcp = pkt[scapy.TCP]
        proto = PROTO_TCP
        payload_len = len(bytes(tcp.payload))
        window = int(tcp.window)
        flags = int(tcp.flags)
        sport, dport = int(tcp.sport), int(tcp.dport)
    elif pkt.haslayer(scapy.UDP):
        udp = pkt[scapy.UDP]
        proto = PROTO_UDP
        payload_len = len(bytes(udp.payload))
        window = 0
        flags = 0
        sport, dport = int(udp.sport), int(udp.dport)
    else:
        return None

    timestamp = float(pkt.time if ts is None else ts)
    wire_len = int(getattr(pkt, "wirelen", 0) or len(pkt))
    return PacketRec(
        ts_us=int(round(timestamp * 1_000_000)),
        proto=proto,
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=sport,
        dst_port=dport,
        payload_len=payload_len,
        wire_len=wire_len,
        tcp_window=window,
        flags=flags,
    )


def make_queue_callback(
    work_queue: "queue.Queue[PacketRec]",
    on_drop: Callable[[int], None] | None = None,
    on_error: Callable[[], None] | None = None,
) -> Callable[[object], None]:
    """Builds a scapy ``prn`` callback that pushes decoded packets to a queue."""

    def callback(pkt) -> None:
        try:
            record = decode_packet(pkt)
        except Exception:  # malformed packet - never kill the sniffer
            if on_error:
                on_error()
            return
        if record is None:
            return
        try:
            work_queue.put_nowait(record)
        except queue.Full:
            if on_drop:
                on_drop(1)

    return callback


class LiveCapture:
    """Live packet capture using a dedicated daemon thread with scapy sniff().

    Uses a plain threading.Thread (not AsyncSniffer) so that the sniffer is
    fully running before Flask's app.run() blocks the main thread.  A
    threading.Event is used to stop the loop cleanly.
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "ip and (tcp or udp)",
        snaplen: int = 256,
        promiscuous: bool = True,
        callback: Callable[[object], None] | None = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promiscuous = promiscuous
        self.callback = callback
        self._stop_event = __import__("threading").Event()
        self._thread: object | None = None

    def start(self) -> None:
        import threading

        log.info(
            "starting live capture on %s (filter=%r, snaplen=%s, promisc=%s)",
            self.interface,
            self.bpf_filter,
            self.snaplen,
            self.promiscuous,
        )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="idsfw-sniffer",
            daemon=True,
        )
        self._thread.start()
        # Give the sniffer thread a moment to open the socket before returning.
        import time
        time.sleep(0.5)
        log.info("live capture thread started (tid=%s)", self._thread.ident)

    def _run(self) -> None:
        """Blocking sniff loop; exits when stop() sets the stop event.

        Opens a raw L2listen socket explicitly (so we can set promisc/snaplen),
        then passes it to scapy.sniff() via opened_socket.  stop_filter is
        polled after every packet so the loop exits cleanly when stop() is called.
        """
        import ctypes
        import socket as _socket

        scapy = scapy_all()
        stop_event = self._stop_event

        # Build the socket with correct promisc + snaplen settings.
        conf = scapy.conf
        sock = conf.L2listen(
            iface=self.interface,
            filter=self.bpf_filter or None,
        )

        # Enable promiscuous mode via SIOCGIFFLAGS / SIOCSIFFLAGS if requested.
        if self.promiscuous:
            try:
                import struct
                import fcntl
                SIOCGIFFLAGS = 0x8913
                SIOCSIFFLAGS = 0x8914
                IFF_PROMISC = 0x100
                ifreq = struct.pack("16sh", self.interface.encode(), 0)
                fd = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
                try:
                    res = fcntl.ioctl(fd.fileno(), SIOCGIFFLAGS, ifreq)
                    flags = struct.unpack("16sh", res)[1]
                    flags |= IFF_PROMISC
                    fcntl.ioctl(fd.fileno(), SIOCSIFFLAGS,
                                struct.pack("16sh", self.interface.encode(), flags))
                finally:
                    fd.close()
            except Exception as exc:
                log.debug("promisc ioctl failed (non-fatal): %s", exc)

        def stop_filter(_pkt) -> bool:
            return stop_event.is_set()

        try:
            scapy.sniff(
                opened_socket=sock,
                prn=self.callback,
                store=False,
                stop_filter=stop_filter,
            )
        except Exception as exc:
            log.error("sniffer thread crashed: %s", exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            try:
                self._thread.join(timeout=3)
            except Exception:
                pass
            self._thread = None


def replay_pcap(
    path: str | Path,
    callback: Callable[[object], None],
    limit: int | None = None,
    realtime: bool = False,
    speed: float = 1.0,
) -> int:
    """Feeds a capture file through ``callback`` (used for offline validation or real-time demo)."""
    import time

    scapy = scapy_all()
    count = 0
    path = Path(path)
    log.info("replaying %s (realtime=%s, speed=%sx)", path, realtime, speed)
    first_pkt_ts = None
    wall_start = time.time()

    with scapy.PcapReader(str(path)) as reader:
        for pkt in reader:
            if realtime:
                orig_ts = float(pkt.time)
                if first_pkt_ts is None:
                    first_pkt_ts = orig_ts
                    wall_start = time.time()
                rel_offset = (orig_ts - first_pkt_ts) / max(0.001, speed)
                target_wall = wall_start + rel_offset
                sleep_dur = target_wall - time.time()
                if 0.001 < sleep_dur < 10.0:
                    time.sleep(sleep_dur)
                pkt.time = time.time()

            callback(pkt)
            count += 1
            if limit and count >= limit:
                break
    log.info("replayed %s packets from %s", count, path)
    return count
