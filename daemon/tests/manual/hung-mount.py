#!/usr/bin/env python3
"""What does a suspend lock do while an unlock is stuck on a file system that stopped answering?

usage: hung-mount.py path/to/omakeepickd

Mounts a small FUSE file system (needs fusermount3, no root) that serves the test fixtures and can
be told to stop answering, like a network mount whose server went away. Then, once with only the
key file on it and once with the database there too, it starts an unlock, sends the lock that
precedes a suspend, and reports how the unlock ended and what the daemon's helper process is doing.

Expected from 0.1.8 on: the unlock ends with `cancelled` at once and the daemon is ready again.
The helper can stay in state D until the mount answers, because FUSE does not let SIGKILL end a
read that is under way, but it was never given the credentials. Up to 0.1.7 the unlock never ends.

Not part of `cargo test`: a test that hangs a file system on purpose should not run unattended.
"""
import array, errno, json, os, select, shutil, socket, stat, struct, subprocess, sys, tempfile, time

INIT, LOOKUP, FORGET, GETATTR, OPEN, READ, RELEASE, FLUSH = 26, 1, 2, 3, 14, 15, 18, 25
OPENDIR, READDIR, RELEASEDIR, ACCESS, INTERRUPT, DESTROY, BATCH_FORGET = 27, 28, 29, 34, 36, 38, 42
PASSWORD = "test-password"


def serve(mnt, src, ctl):
    """The file system: the regular files of `src`, read-only. While `ctl`/hang-read exists, READ
    requests get no answer; while `ctl`/hang-all exists, nothing does. Speaks the raw FUSE protocol
    on the descriptor fusermount3 hands over, so it needs no library."""
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    os.set_inheritable(theirs.fileno(), True)
    mounter = subprocess.Popen(
        ["fusermount3", "-o", "ro,nosuid,nodev,fsname=hangfs,subtype=hangfs", "--", mnt],
        env=dict(os.environ, _FUSE_COMMFD=str(theirs.fileno())), close_fds=False)
    fds = array.array("i")
    _, ancillary, _, _ = ours.recvmsg(1, socket.CMSG_LEN(fds.itemsize))
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            fds.frombytes(data[:fds.itemsize])
    if mounter.wait() != 0 or not fds:
        sys.exit("fusermount3 could not mount")
    fd = fds[0]
    names = sorted(n for n in os.listdir(src) if os.path.isfile(os.path.join(src, n)))
    inode = {n: i + 2 for i, n in enumerate(names)}
    name_of = {i: n for n, i in inode.items()}

    def attr(ino):
        if ino == 1:
            mode, size, mtime = stat.S_IFDIR | 0o755, 0, 0
        else:
            st = os.stat(os.path.join(src, name_of[ino]))
            mode, size, mtime = stat.S_IFREG | 0o644, st.st_size, int(st.st_mtime)
        return struct.pack("<QQQQQQIIIIIIIIII", ino, size, (size + 511) // 512, mtime, mtime, mtime,
                           0, 0, 0, mode, 1, os.getuid(), os.getgid(), 0, 4096, 0)

    def reply(unique, err=0, payload=b""):
        try:
            os.write(fd, struct.pack("<IiQ", 16 + len(payload), -err, unique) + payload)
        except OSError as e:
            if e.errno != errno.ENOENT:  # ENOENT: the request was interrupted meanwhile
                raise

    def handle(request):
        """Answers the request, or returns False to hold it."""
        unique, opcode, nodeid, body = request
        if opcode != INIT and os.path.exists(os.path.join(ctl, "hang-all")):
            return False
        if opcode == READ and os.path.exists(os.path.join(ctl, "hang-read")):
            return False
        if opcode == INIT:
            _, minor, readahead, _ = struct.unpack_from("<IIII", body)
            out = struct.pack("<IIIIHHIIHHII", 7, min(minor, 31), readahead, 0, 12, 9, 1 << 17, 1, 32, 0, 0, 0)
            reply(unique, 0, out.ljust(64, b"\0"))
        elif opcode == LOOKUP:
            name = body.rstrip(b"\0").decode(errors="replace")
            if nodeid == 1 and name in inode:
                reply(unique, 0, struct.pack("<QQQQII", inode[name], 0, 1, 1, 0, 0) + attr(inode[name]))
            else:
                reply(unique, errno.ENOENT)
        elif opcode == GETATTR:
            if nodeid == 1 or nodeid in name_of:
                reply(unique, 0, struct.pack("<QII", 1, 0, 0) + attr(nodeid))
            else:
                reply(unique, errno.ENOENT)
        elif opcode in (OPEN, OPENDIR):
            reply(unique, 0, struct.pack("<QII", 0, 0, 0))
        elif opcode == READ:
            _, offset, size = struct.unpack_from("<QQI", body)
            with open(os.path.join(src, name_of[nodeid]), "rb") as f:
                f.seek(offset)
                reply(unique, 0, f.read(size))
        elif opcode == READDIR:
            reply(unique, 0, b"")
        elif opcode in (RELEASE, FLUSH, RELEASEDIR, ACCESS):
            reply(unique, 0)
        elif opcode in (FORGET, INTERRUPT, BATCH_FORGET):
            pass  # these take no answer
        elif opcode == DESTROY:
            reply(unique, 0)
            sys.exit(0)
        else:
            reply(unique, errno.ENOSYS)
        return True

    held = []
    print("mounted", flush=True)
    os.set_blocking(fd, False)
    while True:
        held = [request for request in held if not handle(request)]
        try:
            buf = os.read(fd, 1 << 20)
        except BlockingIOError:
            time.sleep(0.02)
            continue
        except OSError as e:
            if e.errno == errno.ENODEV:  # unmounted
                return
            if e.errno in (errno.EINTR, errno.ENOENT):
                continue
            raise
        length, opcode, unique, nodeid = struct.unpack_from("<IIQQ", buf)
        request = (unique, opcode, nodeid, buf[40:length])
        if not handle(request):
            held.append(request)


class Daemon:
    """One `omakeepickd serve` with its own runtime and state directories."""

    def __init__(self, binary):
        self.dir = tempfile.mkdtemp(prefix="omakeepick-hung-")
        env = dict(os.environ, OMAKEEPICK_RUNTIME_DIR=self.dir + "/run",
                   OMAKEEPICK_STATE_DIR=self.dir + "/state", OMAKEEPICK_NO_LOGIND="1")
        self.process = subprocess.Popen([binary, "serve"], env=env, stdin=subprocess.DEVNULL,
                                        stderr=open(self.dir + "/log", "w"))
        for _ in range(250):
            try:
                self.socket = socket.socket(socket.AF_UNIX)
                self.socket.connect(self.dir + "/run/sock")
                break
            except OSError:
                time.sleep(0.02)
        else:
            sys.exit("the daemon did not start")
        self.buffered = b""

    def send(self, id, cmd, **args):
        self.socket.sendall((json.dumps(dict(args, id=id, cmd=cmd)) + "\n").encode())

    def reply(self, id, timeout):
        """The reply to request `id`, or None if it does not come in time."""
        deadline = time.monotonic() + timeout
        while True:
            while b"\n" in self.buffered:
                line, self.buffered = self.buffered.split(b"\n", 1)
                message = json.loads(line)
                if message.get("id") == id:
                    return message
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.socket], [], [], left)[0]:
                return None
            chunk = self.socket.recv(65536)
            if not chunk:
                return None
            self.buffered += chunk

    def busy(self):
        self.send(900, "status")
        status = self.reply(900, 3)
        return status["state"]["busy"] if status else "no answer"

    def helpers(self):
        """The daemon's child processes, as (pid, state) from /proc."""
        found = []
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                fields = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
            except OSError:
                continue
            if int(fields[1]) == self.process.pid:
                found.append((int(pid), fields[0]))
        return found

    def log(self):
        return [line for line in open(self.dir + "/log").read().splitlines() if "listening on" not in line]


def scenario(binary, mnt, src, ctl, only_the_key_file):
    daemon = Daemon(binary)
    db = os.path.join(src if only_the_key_file else mnt, "Secrets.kdbx")
    unlock = dict(db=db, keyfile=os.path.join(mnt, "Secrets.keyx"), password=PASSWORD)
    flag = os.path.join(ctl, "hang-read" if only_the_key_file else "hang-all")
    try:
        daemon.send(1, "unlock", **unlock)
        print("  while the mount answers, unlock:", daemon.reply(1, 30))
        daemon.send(2, "close")
        daemon.reply(2, 3)
        # The daemon starts watching the database's directory right after an unlock. Let that
        # finish while the mount still answers: this is about the unlock that comes next.
        time.sleep(1)

        open(flag, "w").close()
        daemon.send(3, "unlock", **unlock)
        time.sleep(1.5)
        print(f"  the mount is silent, unlock sent: busy={daemon.busy()}, helpers={daemon.helpers()}")
        daemon.send(4, "lock", reason="sleep")
        locked = time.monotonic()
        daemon.reply(4, 3)
        answer = daemon.reply(3, 6)
        waited = time.monotonic() - locked
        if answer:
            print(f"  lock (sleep): the unlock ended {waited:.2f}s later with {answer.get('error')!r}")
        else:
            print(f"  lock (sleep): the unlock has NOT ended {waited:.0f}s later")
        print(f"  after the lock: busy={daemon.busy()}, helpers={daemon.helpers()}")
        daemon.send(5, "quit")
        asked = time.monotonic()
        try:
            daemon.process.wait(10)
            print(f"  quit: the daemon exited after {time.monotonic() - asked:.2f}s")
        except subprocess.TimeoutExpired:
            print("  quit: the daemon is still there 10s later")
    finally:
        if os.path.exists(flag):
            os.remove(flag)  # the mount answers again; anything stuck on it can end
        time.sleep(0.5)
        if daemon.process.poll() is None:
            daemon.process.kill()
        for line in daemon.log():
            print("  log:", line)
        shutil.rmtree(daemon.dir, ignore_errors=True)


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--serve":
        return serve(*sys.argv[2:])
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    binary = os.path.abspath(sys.argv[1])
    fixtures = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")
    work = tempfile.mkdtemp(prefix="omakeepick-hangfs-")
    mnt, src, ctl = (os.path.join(work, name) for name in ("mnt", "src", "ctl"))
    for directory in (mnt, src, ctl):
        os.mkdir(directory)
    shutil.copy(os.path.join(fixtures, "password-keyfile.kdbx"), os.path.join(src, "Secrets.kdbx"))
    shutil.copy(os.path.join(fixtures, "password-keyfile.keyx"), os.path.join(src, "Secrets.keyx"))
    server = subprocess.Popen([sys.executable, os.path.abspath(__file__), "--serve", mnt, src, ctl],
                              stdout=subprocess.PIPE, text=True)
    if server.stdout.readline().strip() != "mounted":
        sys.exit("could not mount the test file system (is fusermount3 installed?)")
    try:
        print(subprocess.run([binary, "--version"], capture_output=True, text=True).stdout.strip())
        print("The key file is on the mount that goes silent:")
        scenario(binary, mnt, src, ctl, only_the_key_file=True)
        print("The database and the key file are:")
        scenario(binary, mnt, src, ctl, only_the_key_file=False)
    finally:
        subprocess.run(["fusermount3", "-u", "-z", mnt])
        try:
            server.wait(5)
        except subprocess.TimeoutExpired:
            server.kill()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
