// The $errno WITX enum defined in WASI preview 1.
const errno = {
    "success": 0,
    "2big": 1,
    "acces": 2,
    "addrinuse": 3,
    "addrnotavail": 4,
    "afnosupport": 5,
    "again": 6,
    "already": 7,
    "badf": 8,
    "badmsg": 9,
    "busy": 10,
    "canceled": 11,
    "child": 12,
    "connaborted": 13,
    "connrefused": 14,
    "connreset": 15,
    "deadlk": 16,
    "destaddrreq": 17,
    "dom": 18,
    "dquot": 19,
    "exist": 20,
    "fault": 21,
    "fbig": 22,
    "hostunreach": 23,
    "idrm": 24,
    "ilseq": 25,
    "inprogress": 26,
    "intr": 27,
    "inval": 28,
    "io": 29,
    "isconn": 30,
    "isdir": 31,
    "loop": 32,
    "mfile": 33,
    "mlink": 34,
    "msgsize": 35,
    "multihop": 36,
    "nametoolong": 37,
    "netdown": 38,
    "netreset": 39,
    "netunreach": 40,
    "nfile": 41,
    "nobufs": 42,
    "nodev": 43,
    "noent": 44,
    "noexec": 45,
    "nolck": 46,
    "nolink": 47,
    "nomem": 48,
    "nomsg": 49,
    "noprotoopt": 50,
    "nospc": 51,
    "nosys": 52,
    "notconn": 53,
    "notdir": 54,
    "notempty": 55,
    "notrecoverable": 56,
    "notsock": 57,
    "notsup": 58,
    "notty": 59,
    "nxio": 60,
    "overflow": 61,
    "ownerdead": 62,
    "perm": 63,
    "pipe": 64,
    "proto": 65,
    "protonosupport": 66,
    "prototype": 67,
    "range": 68,
    "rofs": 69,
    "spipe": 70,
    "srch": 71,
    "stale": 72,
    "timedout": 73,
    "txtbsy": 74,
    "xdev": 75,
    "notcapable": 76,
};

// The $filetype WITX enum defined in WASI preview 1.
const filetype = {
    "unknown": 0,
    "block_device": 1,
    "character_device": 2,
    "directory": 3,
    "regular_file": 4,
    "socket_dgram": 5,
    "socket_stream": 6,
    "symbolic_link": 7,
};

// The $fdflags WITX flags defined in WASI preview 1.
const fdflags = {
    "append": 1,
    "dsync": 2,
    "nonblock": 4,
    "rsync": 8,
    "sync": 16,
};

// The $rights WITX flags defined in WASI preview 1.
const rights = {
    "fd_datasync": 1n << 0n,
    "fd_read": 1n << 1n,
    "fd_seek": 1n << 2n,
    "fd_fdstat_set_flags": 1n << 3n,
    "fd_sync": 1n << 4n,
    "fd_tell": 1n << 5n,
    "fd_write": 1n << 6n,
    "fd_advise": 1n << 7n,
    "fd_allocate": 1n << 8n,
    "path_create_directory": 1n << 9n,
    "path_create_file": 1n << 10n,
    "path_link_source": 1n << 11n,
    "path_link_target": 1n << 12n,
    "path_open": 1n << 13n,
    "fd_readdir": 1n << 14n,
    "path_readlink": 1n << 15n,
    "path_rename_source": 1n << 16n,
    "path_rename_target": 1n << 17n,
    "path_filestat_get": 1n << 18n,
    "path_filestat_set_size": 1n << 19n,
    "path_filestat_set_times": 1n << 20n,
    "fd_filestat_get": 1n << 21n,
    "fd_filestat_set_size": 1n << 22n,
    "fd_filestat_set_times": 1n << 23n,
    "path_symlink": 1n << 24n,
    "path_remove_directory": 1n << 25n,
    "path_unlink_file": 1n << 26n,
    "poll_fd_readwrite": 1n << 27n,
    "sock_shutdown": 1n << 28n,
    "sock_accept": 1n << 29n,
};

// The $oflags WITX flags defined in WASI preview 1.
const oflags = {
    "creat": 1,
    "directory": 2,
    "excl": 4,
    "trunc": 8,
};

class FdStat {
    constructor(fileType, flags, rightsBase, rightsInheriting) {
        this.fileType = fileType;
        this.flags = flags;
        this.rightsBase = rightsBase;
        this.rightsInheriting = rightsInheriting;
    }

    write(dataView, pointer) {
        dataView.setUint8(pointer, this.fileType);
        dataView.setUint16(pointer + 2, this.flags, true);
        dataView.setBigUint64(pointer + 8, this.rightsBase, true);
        dataView.setBigUint64(pointer + 16, this.rightsInheriting, true);
    }
}

class FileDescriptor {
    constructor(file, fdFlags) {
        this.file = file;
        this.fdFlags = fdFlags;
        this.position = 0;
    }

    stat() {
        return new FdStat(
            this.file.fileType(),
            this.fdFlags,
            rights.fd_read | rights.fd_write,
            rights.fd_read | rights.fd_write
        )
    }

    writev(system, ptrIovecArray, lengthIovecArray) {
        let [status, size] = this.file.writev(system, this.position, ptrIovecArray, lengthIovecArray);
        this.position += size;
        return [status, size];
    }

    readv(system, ptrIovecArray, lengthIovecArray) {
        let [status, size] = this.file.readv(system, this.position, ptrIovecArray, lengthIovecArray);
        this.position += size;
        return [status, size];
    }
}

class FileSystem {
    constructor() {
        this.nextInode = 0n;
    }

    inode() {
        return this.nextInode++;
    }
}

// A virtual file representing stdout or stderr.
class OutputPipe {
    constructor(fileSystem) {
        this.inode = fileSystem.inode();
    }

    fileType() {
        return filetype.regular_file;
    }

    rights() {
        return rights.fd_write;
    }

    writev(system, _position, ptrIovecArray, lengthIovecArray) {
        let bufferSize = 0;
        for (let i = 0; i < lengthIovecArray; i++) {
            let bufLen = system.dataView.getUint32(ptrIovecArray + i * 8 + 4, true);
            bufferSize += bufLen;
        }

        let buffer = new ArrayBuffer(bufferSize);
        let bufferArray = new Uint8Array(buffer);
        let size = 0;
        for (let i = 0; i < lengthIovecArray; i++) {
            let buf = system.dataView.getUint32(ptrIovecArray + i * 8, true);
            let bufLen = system.dataView.getUint32(ptrIovecArray + i * 8 + 4, true);
            bufferArray.set(system.byteArray.subarray(buf, buf + bufLen), size);
            size += bufLen;
        }

        globalThis.postMessage(
            {
                "kind": "pty_write",
                "buffer": buffer,
            },
            [buffer]
        );

        return [errno.success, size];
    }

    // Returns information about preopened file descriptors.
    //
    // * Whether or not this is a preopened file descriptor.
    // * Whether or not this preopened file descriptor is for a directory.
    // * The name of the preopened directory, if applicable.
    prestat() {
        return [false, false, new Uint8Array()];
    }
}

class VirtualDirectory {
    constructor(isPreopened, preopenedName, fileSystem) {
        this.isPreopened = isPreopened;
        this.name = preopenedName;
        if (typeof preopenedName === "string") {
            this.nameBuffer = new TextEncoder().encode(preopenedName);
        } else {
            this.nameBuffer = null;
        }
        this.children = new Map();

        this.inode = fileSystem.inode();
}

    fileType() {
        return filetype.directory;
    }

    rights() {
        return rights.fd_readdir | rights.path_create_directory;
    }

    writev() {
        return [errno.badf, 0];
    }

    // Returns information about preopened file descriptors.
    //
    // * Whether or not this is a preopened file descriptor.
    // * Whether or not this preopened file descriptor is for a directory.
    // * The name of the preopened directory, if applicable.
    prestat() {
        if (this.isPreopened) {
            return [true, true, this.nameBuffer];
        } else {
            return [false, false, new Uint8Array()];
        }
    }
}

class VirtualFile {
    constructor(fileSystem) {
        this.truncate();

        this.inode = fileSystem.inode();
    }

    truncate() {
        this.contents = new ArrayBuffer(0, { maxByteLength: 1 << 30 });
    }

    fileType() {
        return filetype.regular_file;
    }

    rights() {
        return rights.fd_read | rights.fd_write;
    }

    writev(system, position, ptrIovecArray, lengthIovecArray) {
        let totalSize = 0;
        for (let i = 0; i < lengthIovecArray; i++) {
            let bufLen = system.dataView.getUint32(ptrIovecArray + i * 8 + 4, true);
            totalSize += bufLen;
        }

        let finalPosition = position + totalSize;
        if (finalPosition > this.contents.byteLength) {
            this.contents.resize(finalPosition);
        }

        let size = 0;
        let contentsArray = new Uint8Array(this.contents);
        for (let i = 0; i < lengthIovecArray; i++) {
            let buf = system.dataView.getUint32(ptrIovecArray + i * 8, true);
            let bufLen = system.dataView.getUint32(ptrIovecArray + i * 8 + 4, true);
            contentsArray.set(system.byteArray.subarray(buf, buf + bufLen), position);
            position += bufLen;
            size += bufLen;
        }
        return [errno.success, size];
    }

    readv(system, position, ptrIovecArray, lengthIovecArray) {
        let size = 0;
        let contentsArray = new Uint8Array(this.contents);
        for (let i = 0; i < lengthIovecArray; i++) {
            let buf = system.dataView.getUint32(ptrIovecArray + i * 8, true);
            let bufLen = system.dataView.getUint32(ptrIovecArray + i * 8 + 4, true);
            let count = Math.min(bufLen, contentsArray.length - position);
            system.byteArray.set(contentsArray.subarray(position, position + count), buf);
            position += count;
            size += count;
            if (position === contentsArray.length) {
                break;
            }
        }
        return [errno.success, size];
    }

    prestat() {
        return [false, false, new Uint8Array()];
    }
}

class FdTable {
    constructor() {
        this.map = new Map();
        this.nextFd = 0;
    }

    get(fd) {
        return this.map.get(fd);
    }

    set(fd, file, fdFlags) {
        if (!fdFlags) {
            fdFlags = 0;
        }
        this.map.set(fd, new FileDescriptor(file, fdFlags));
    }

    add(file, fdFlags) {
        if (!fdFlags) {
            fdFlags = 0;
        }
        const fd = this.nextFd;
        this.nextFd++;
        this.map.set(fd, new FileDescriptor(file, fdFlags));
        return fd;
    }
}

class SerializedArgs {
    constructor(args) {
        this.offsets = new Array(args.length);

        // Start with one byte per argument for null terminators.
        let bufferLength = args.length;
        for (let arg of args) {
            // Add three bytes per character, to guarantee that encoding will
            // succeed.
            bufferLength += arg.length * 3;
        }
        this.buffer = new ArrayBuffer(bufferLength);

        let encoder = new TextEncoder();
        let array = new Uint8Array(this.buffer);
        let position = 0;
        for (let i = 0; i < args.length; i++) {
            this.offsets[i] = position;
            let result = encoder.encodeInto(args[i], array.subarray(position));
            position += result.written;
            array.fill(0, position, position + 1);
            position += 1;
        }
    }
}

class Process {
    constructor(args) {
        this.serializedArgs = new SerializedArgs(args);
        this.fdTable = new FdTable();
    }
}

class WasiSystem {
    #exports;
    #dataView;
    #byteArray;

    constructor() {
        this.fileSystem = new FileSystem();

        this.process = new Process(["a.out", "--bench"]);

        // Populate the process's file descriptor table with stdout, stderr, and
        // a preopened directory.
        this.process.fdTable.set(1, new OutputPipe(this.fileSystem));
        this.process.fdTable.set(2, new OutputPipe(this.fileSystem));
        const rootDirectory = new VirtualDirectory(true, ".", this.fileSystem);
        this.process.fdTable.set(3, rootDirectory);
        this.process.fdTable.nextFd = 4;
    }

    set exports(exports) {
        this.#exports = exports;
        this.#dataView = undefined;
        this.#byteArray = undefined;
    }

    get dataView() {
        // Check if the data view has not been initialized yet, or the underlying
        // memory buffer has been detached.
        if (this.#dataView === undefined || this.#dataView.buffer.detached === true) {
            this.#dataView = new DataView(this.#exports.memory.buffer);
        }
        return this.#dataView;
    }

    get byteArray() {
        // Check if the byte array has not been initialized yet, or the memory
        // buffer has been resized.
        if (this.#byteArray === undefined || this.#byteArray.byteLength === 0) {
            this.#byteArray = new Uint8Array(this.#exports.memory.buffer);
        }
        return this.#byteArray;
    }

    // Produces an imports object providing WASI functions.
    imports() {
        return {
            "wasi_snapshot_preview1": {
                "args_sizes_get": (ptrNumArgs, ptrDataSize) => this.args_sizes_get(ptrNumArgs, ptrDataSize),
                "args_get": (ptrArgv, ptrArgvBuf) => this.args_get(ptrArgv, ptrArgvBuf),
                "random_get": (ptr, len) => this.random_get(ptr, len),
                "clock_time_get": (clockId, precision, ptrTimestamp) => this.clock_time_get(clockId, precision, ptrTimestamp),
                "fd_read": (fd, ptrIovecArray, lengthIovecArray, ptrSize) => this.fd_read(fd, ptrIovecArray, lengthIovecArray, ptrSize),
                "fd_write": (fd, ptrIovecArray, lengthIovecArray, ptrSize) => this.fd_write(fd, ptrIovecArray, lengthIovecArray, ptrSize),
                "fd_filestat_get": (fd, ptrFilestat) => this.fd_filestat_get(fd, ptrFilestat),
                "path_create_directory": (fd, ptrPath, lengthPath) => this.path_create_directory(fd, ptrPath, lengthPath),
                "path_filestat_get": (fd, lookupFlags, ptrPath, lengthPath, ptrFilestat) => this.path_filestat_get(fd, lookupFlags, ptrPath, lengthPath, ptrFilestat),
                "path_open": (fd, lookupFlags, ptrPath, lengthPath, openFlags, rightsBase, rightsInheriting, fdFlags, ptrFdOut) => this.path_open(fd, lookupFlags, ptrPath, lengthPath, openFlags, rightsBase, rightsInheriting, fdFlags, ptrFdOut),
                "fd_readdir": () => this.fd_readdir(),
                "environ_get": (ptrEnviron, ptrEnvironBuf) => this.environ_get(ptrEnviron, ptrEnvironBuf),
                "environ_sizes_get": (ptrNumVars, ptrDataSize) => this.environ_sizes_get(ptrNumVars, ptrDataSize),
                "fd_close": (fd) => this.fd_close(fd),
                "fd_fdstat_get": (fd, ptrStat) => this.fd_fdstat_get(fd, ptrStat),
                "fd_prestat_get": (fd, ptrPrestat) => this.fd_prestat_get(fd, ptrPrestat),
                "fd_prestat_dir_name": (fd, ptrPath, lengthPath) => this.fd_prestat_dir_name(fd, ptrPath, lengthPath),
                "proc_exit": () => this.proc_exit(),
            },
        };
    }

    // Helper method to write a filestat structure.
    //
    // This is used in the implementation of fd_filestat_get and path_filestat_get.
    writeFilestat(file, ptrFilestat) {
        let fileSize = 0n;
        if (file instanceof VirtualFile) {
            fileSize = BigInt(file.contents.byteLength);
        }

        // Device ID
        this.dataView.setBigUint64(ptrFilestat, 0n, true);
        // File inode
        this.dataView.setBigUint64(ptrFilestat + 8, file.inode, true);
        // File type
        this.dataView.setUint8(ptrFilestat + 16, file.fileType());
        // Number of hard links
        this.dataView.setBigUint64(ptrFilestat + 24, 0n, true);
        // File size
        this.dataView.setBigUint64(ptrFilestat + 32, fileSize, true);
        // Access time
        this.dataView.setBigUint64(ptrFilestat + 40, 0n, true);
        // Modification time
        this.dataView.setBigUint64(ptrFilestat + 48, 0n, true);
        // Status change time
        this.dataView.setBigUint64(ptrFilestat + 56, 0n, true);
    }

    // ;;; Return command-line argument data sizes.
    // (@interface func (export "args_sizes_get")
    //   ;;; Returns the number of arguments and the size of the argument string
    //   ;;; data, or an error.
    //   (result $error (expected (tuple $size $size) (error $errno)))
    // )
    //
    // (typename $size u32)
    //
    // WASM function type: (func (param i32 i32) (result i32))
    args_sizes_get(ptrNumArgs, ptrDataSize) {
        this.dataView.setUint32(ptrNumArgs, this.process.serializedArgs.offsets.length, true);
        this.dataView.setUint32(ptrDataSize, this.process.serializedArgs.buffer.byteLength, true);
        return errno.success;
    }

    // ;;; Read command-line argument data.
    // ;;;
    // ;;; The size of the array should match that returned by `args_sizes_get`.
    // ;;;
    // ;;; Each argument is expected to be `\0` terminated.
    // ;;;
    // ;;; The first argument should be a string containing the "name" of the
    // ;;; program. This need not be a usable filesystem path or even file name,
    // ;;; and may even be a fixed string. Subsequent arguments are the arguments
    // ;;; passed to the program by the user.
    // (@interface func (export "args_get")
    //   (param $argv (@witx pointer (@witx pointer u8)))
    //   (param $argv_buf (@witx pointer u8))
    //   (result $error (expected (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32) (result i32))
    args_get(ptrArgv, ptrArgvBuf) {
        for (let i = 0; i < this.process.serializedArgs.offsets.length; i++) {
            this.dataView.setUint32(
                ptrArgv + i * 4,
                ptrArgvBuf + this.process.serializedArgs.offsets[i],
                true
            );
        }
        this.byteArray.set(new Uint8Array(this.process.serializedArgs.buffer), ptrArgvBuf);
        return errno.success;
    }

    // ;;; Write high-quality random data into a buffer.
    // ;;; This function blocks when the implementation is unable to immediately
    // ;;; provide sufficient high-quality random data.
    // (@interface func (export "random_get")
    //   ;;; The buffer to fill with random data.
    //   (param $buf (@witx pointer u8))
    //   (param $buf_len $size)
    //   (result $error (expected (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32) (result i32))
    random_get(ptr, len) {
        crypto.getRandomValues(this.byteArray.subarray(ptr, len));
        return errno.success;
    }

    // ;;; Return the time value of a clock.
    // ;;; Note: This is similar to `clock_gettime` in POSIX.
    // (@interface func (export "clock_time_get")
    //   ;;; The clock for which to return the time.
    //   (param $id $clockid)
    //   ;;; The maximum lag (exclusive) that the returned time value may have, compared to its actual value.
    //   (param $precision $timestamp)
    //   ;;; The time value of the clock.
    //   (result $error (expected $timestamp (error $errno)))
    // )
    //
    // ;;; Timestamp in nanoseconds.
    // (typename $timestamp u64)
    //
    // WASM function type: (func (param i32 i64 i32) (result i32))
    clock_time_get(clockId, _precision, ptrTimestamp) {
        if (clockId == 0) {
            // $realtime
            //
            // This returns a Unix timestamp.
            this.dataView.setBigUint64(
                ptrTimestamp,
                BigInt(Math.round(Date.now() * 1000000)),
                true
            );
            return errno.success;
        } else if (clockId = 1) {
            // $monotonic
            this.dataView.setBigUint64(
                ptrTimestamp,
                BigInt(Math.round(performance.now() * 1000000)),
                true
            );
            return errno.success;
        } else if (clockId = 2) {
            // $process_cputime_id
            return errno.badf;
        } else if (clockId = 3) {
            // $thread_cputime_id
            return errno.badf;
        }
    }

    // ;;; Read from a file descriptor.
    // ;;; Note: This is similar to `readv` in POSIX.
    // (@interface func (export "fd_read")
    //   (param $fd $fd)
    //   ;;; List of scatter/gather vectors to which to store data.
    //   (param $iovs $iovec_array)
    //   ;;; The number of bytes read.
    //   (result $error (expected $size (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32 i32 i32) (result i32))
    fd_read(fd, ptrIovecArray, lengthIovecArray, ptrSize) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }
        let [status, size] = fileDescriptor.readv(this, ptrIovecArray, lengthIovecArray);
        this.dataView.setUint32(ptrSize, size, true);
        return status;
    }

    // ;;; Write to a file descriptor.
    // ;;; Note: This is similar to `writev` in POSIX.
    // ;;;
    // ;;; Like POSIX, any calls of `write` (and other functions to read or write)
    // ;;; for a regular file by other threads in the WASI process should not be
    // ;;; interleaved while `write` is executed.
    // (@interface func (export "fd_write")
    //   (param $fd $fd)
    //   ;;; List of scatter/gather vectors from which to retrieve data.
    //   (param $iovs $ciovec_array)
    //   (result $error (expected $size (error $errno)))
    // )
    //
    // (typename $ciovec_array (list $ciovec))
    //
    // ;;; A region of memory for scatter/gather writes.
    // (typename $ciovec
    //   (record
    //     ;;; The address of the buffer to be written.
    //     (field $buf (@witx const_pointer u8))
    //     ;;; The length of the buffer to be written.
    //     (field $buf_len $size)
    //   )
    // )
    //
    // (typename $size u32)
    //
    // WASM function type: (func (param i32 i32 i32 i32) (result i32))
    fd_write(fd, ptrIovecArray, lengthIovecArray, ptrSize) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }
        let [status, size] = fileDescriptor.writev(this, ptrIovecArray, lengthIovecArray);
        this.dataView.setUint32(ptrSize, size, true);
        return status;
    }

    // ;;; Return the attributes of an open file.
    // (@interface func (export "fd_filestat_get")
    //   (param $fd $fd)
    //   ;;; The buffer where the file's attributes are stored.
    //   (result $error (expected $filestat (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32) (result i32))
    fd_filestat_get(fd, ptrFilestat) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }

        this.writeFilestat(fileDescriptor.file, ptrFilestat);

        return errno.success;
    }

    // ;;; Create a directory.
    // ;;; Note: This is similar to `mkdirat` in POSIX.
    // (@interface func (export "path_create_directory")
    //   (param $fd $fd)
    //   ;;; The path at which to create the directory.
    //   (param $path string)
    //   (result $error (expected (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32 i32) (result i32))
    path_create_directory(fd, ptrPath, lengthPath) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }

        let slice = this.byteArray.subarray(ptrPath, ptrPath + lengthPath);
        let decoder = new TextDecoder();
        let path = decoder.decode(slice);

        let file = fileDescriptor.file;
        for (let segment of path.split("/")) {
            if (file.fileType() !== filetype.directory) {
                return errno.badf;
            }
            if (file.children.has(segment)) {
                file = file.children.get(segment);
            } else {
                let newDirectory = new VirtualDirectory(false, null, this.fileSystem);
                file.children.set(segment, newDirectory);
                file = newDirectory;
            }
        }
        return errno.success;
    }

    // ;;; Return the attributes of a file or directory.
    // ;;; Note: This is similar to `stat` in POSIX.
    // (@interface func (export "path_filestat_get")
    //   (param $fd $fd)
    //   ;;; Flags determining the method of how the path is resolved.
    //   (param $flags $lookupflags)
    //   ;;; The path of the file or directory to inspect.
    //   (param $path string)
    //   ;;; The buffer where the file's attributes are stored.
    //   (result $error (expected $filestat (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32 i32 i32 i32) (result i32))
    path_filestat_get(fd, _lookupFlags, ptrPath, lengthPath, ptrFilestat) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }

        let slice = this.byteArray.subarray(ptrPath, ptrPath + lengthPath);
        let decoder = new TextDecoder();
        let path = decoder.decode(slice);

        let file = fileDescriptor.file;
        let segments = path.split("/");
        for (let segment of segments) {
            if (file.fileType() !== filetype.directory) {
                return errno.badf;
            }
            if (file.children.has(segment)) {
                file = file.children.get(segment);
            } else {
                return errno.noent;
            }
        }

        this.writeFilestat(file, ptrFilestat);

        return errno.success;
    }

    // ;;; Open a file or directory.
    // ;;
    // ;;; The returned file descriptor is not guaranteed to be the lowest-numbered
    // ;;; file descriptor not currently open; it is randomized to prevent
    // ;;; applications from depending on making assumptions about indexes, since this
    // ;;; is error-prone in multi-threaded contexts. The returned file descriptor is
    // ;;; guaranteed to be less than 2**31.
    // ;;
    // ;;; Note: This is similar to `openat` in POSIX.
    // (@interface func (export "path_open")
    //   (param $fd $fd)
    //   ;;; Flags determining the method of how the path is resolved.
    //   (param $dirflags $lookupflags)
    //   ;;; The relative path of the file or directory to open, relative to the
    //   ;;; `path_open::fd` directory.
    //   (param $path string)
    //   ;;; The method by which to open the file.
    //   (param $oflags $oflags)
    //   ;;; The initial rights of the newly created file descriptor. The
    //   ;;; implementation is allowed to return a file descriptor with fewer rights
    //   ;;; than specified, if and only if those rights do not apply to the type of
    //   ;;; file being opened.
    //   ;;
    //   ;;; The *base* rights are rights that will apply to operations using the file
    //   ;;; descriptor itself, while the *inheriting* rights are rights that apply to
    //   ;;; file descriptors derived from it.
    //   (param $fs_rights_base $rights)
    //   (param $fs_rights_inheriting $rights)
    //   (param $fdflags $fdflags)
    //   ;;; The file descriptor of the file that has been opened.
    //   (result $error (expected $fd (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32))
    path_open(
        fd,
        _lookupFlags,
        ptrPath,
        lengthPath,
        openFlags,
        _rightsBase,
        _rightsInheriting,
        fdFlags,
        ptrFdOut
    ) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }

        if (fdFlags !== 0) {
            console.error("unsupported fdflags:", fdFlags);
            return errno.acces;
        }

        let slice = this.byteArray.subarray(ptrPath, ptrPath + lengthPath);
        let decoder = new TextDecoder();
        let path = decoder.decode(slice);

        let segments = path.split("/");
        let file = fileDescriptor.file;
        for (let i = 0; i < segments.length - 1; i++) {
            if (file.fileType() !== filetype.directory) {
                return errno.badf;
            }
            if (file.children.has(segments[i])) {
                file = file.children.get(segments[i]);
            } else {
                return errno.noent;
            }
        }

        if (file.fileType() !== filetype.directory) {
            return errno.badf;
        }

        let lastSegment = segments[segments.length - 1];
        let newFd;
        if (file.children.has(lastSegment)) {
            if ((openFlags & oflags.excl) !== 0) {
                return errno.exist;
            }
            let existingFile = file.children.get(lastSegment);
            if ((openFlags & oflags.directory) !== 0 && !(file instanceof VirtualDirectory)) {
                return errno.notdir;
            }
            if ((openFlags & oflags.trunc) !== 0) {
                if (!(existingFile instanceof VirtualFile)) {
                    console.error(`tried to truncate ${path} which is ${existingFile}`, existingFile);
                    return errno.acces;
                }
                existingFile.truncate();
            }
            newFd = this.process.fdTable.add(existingFile);
        } else {
            if ((openFlags & oflags.creat) === 0) {
                return errno.noent;
            }
            let newFile = new VirtualFile(this.fileSystem);
            file.children.set(lastSegment, newFile);
            newFd = this.process.fdTable.add(newFile);
        }

        this.dataView.setUint32(ptrFdOut, newFd, true);
        return errno.success;
    }

    // ;;; Read directory entries from a directory.
    // ;;; When successful, the contents of the output buffer consist of a sequence of
    // ;;; directory entries. Each directory entry consists of a `dirent` object,
    // ;;; followed by `dirent::d_namlen` bytes holding the name of the directory
    // ;;; entry.
    // ;;
    // ;;; This function fills the output buffer as much as possible, potentially
    // ;;; truncating the last directory entry. This allows the caller to grow its
    // ;;; read buffer size in case it's too small to fit a single large directory
    // ;;; entry, or skip the oversized directory entry.
    // ;;;
    // ;;; Entries for the special `.` and `..` directory entries are included in the
    // ;;; sequence.
    // (@interface func (export "fd_readdir")
    //   (param $fd $fd)
    //   ;;; The buffer where directory entries are stored
    //   (param $buf (@witx pointer u8))
    //   (param $buf_len $size)
    //   ;;; The location within the directory to start reading
    //   (param $cookie $dircookie)
    //   ;;; The number of bytes stored in the read buffer. If less than the size of the read buffer, the end of the directory has been reached.
    //   (result $error (expected $size (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32 i32 i64 i32) (result i32))
    fd_readdir() {
        throw new Error("fd_readdir not implemented");
    }

    // ;;; Read environment variable data.
    // ;;; The sizes of the buffers should match that returned by `environ_sizes_get`.
    // ;;; Key/value pairs are expected to be joined with `=`s, and terminated with `\0`s.
    // (@interface func (export "environ_get")
    //   (param $environ (@witx pointer (@witx pointer u8)))
    //   (param $environ_buf (@witx pointer u8))
    //   (result $error (expected (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32) (result i32))
    environ_get(_ptrEnviron, _ptrEnvironBuf) {
        return errno.success;
    }

    // ;;; Return environment variable data sizes.
    // (@interface func (export "environ_sizes_get")
    //   ;;; Returns the number of environment variable arguments and the size of the
    //   ;;; environment variable data.
    //   (result $error (expected (tuple $size $size) (error $errno)))
    // )
    //
    // (typename $size u32)
    //
    // WASM function type: (func (param i32 i32) (result i32))
    environ_sizes_get(ptrNumVars, ptrDataSize) {
        this.dataView.setUint32(ptrNumVars, 0, true);
        this.dataView.setUint32(ptrDataSize, 0, true);
        return errno.success;
    }

    // ;;; Close a file descriptor.
    // ;;; Note: This is similar to `close` in POSIX.
    // (@interface func (export "fd_close")
    //   (param $fd $fd)
    //   (result $error (expected (error $errno)))
    // )
    //
    // WASM function type: (func (param i32) (result i32))
    fd_close(fd) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }
        // Leave the file descriptor in the table anyway.
        return errno.success;
    }

    // ;;; Get the attributes of a file descriptor.
    // ;;; Note: This returns similar flags to `fcntl(fd, F_GETFL)` in POSIX, as well as additional fields.
    // (@interface func (export "fd_fdstat_get")
    //   (param $fd $fd)
    //   ;;; The buffer where the file descriptor's attributes are stored.
    //   (result $error (expected $fdstat (error $errno)))
    // )
    //
    // (typename $fd (handle))
    //
    // ;;; File descriptor attributes.
    // (typename $fdstat
    //   (record
    //     ;;; File type.
    //     (field $fs_filetype $filetype)
    //     ;;; File descriptor flags.
    //     (field $fs_flags $fdflags)
    //     ;;; Rights that apply to this file descriptor.
    //     (field $fs_rights_base $rights)
    //     ;;; Maximum set of rights that may be installed on new file descriptors that
    //     ;;; are created through this file descriptor, e.g., through `path_open`.
    //     (field $fs_rights_inheriting $rights)
    //   )
    // )
    //
    // WASM function type: (func (param i32 i32) (result i32))
    fd_fdstat_get(fd, ptrStat) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }
        fileDescriptor.stat().write(this.dataView, ptrStat);
        return errno.success;
    }

    // ;;; Return a description of the given preopened file descriptor.
    // (@interface func (export "fd_prestat_get")
    //   (param $fd $fd)
    //   ;;; The buffer where the description is stored.
    //   (result $error (expected $prestat (error $errno)))
    // )
    //
    // (typename $prestat
    //   (union (@witx tag $preopentype)
    //     $prestat_dir
    //   )
    // )
    //
    // ;;; The contents of a `prestat` when type is `preopentype::dir`.
    // (typename $prestat_dir
    //   (record
    //     ;;; The length of the directory name for use with `fd_prestat_dir_name`.
    //     (field $pr_name_len $size)
    //   )
    // )
    //
    // WASM function type: (func (param i32 i32) (result i32))
    fd_prestat_get(fd, ptrPrestat) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }
        let [isPreopened, isPreopenedDir, name] = fileDescriptor.file.prestat();
        if (!isPreopened) {
            return errno.badf;
        }
        if (!isPreopenedDir) {
            return errno.badf;
        }
        this.dataView.setUint8(ptrPrestat, 0); // union tag
        this.dataView.setUint32(ptrPrestat + 4, name.byteLength, true);
        return errno.success;
    }

    // ;;; Return a description of the given preopened file descriptor.
    // (@interface func (export "fd_prestat_dir_name")
    //   (param $fd $fd)
    //   ;;; A buffer into which to write the preopened directory name.
    //   (param $path (@witx pointer u8))
    //   (param $path_len $size)
    //   (result $error (expected (error $errno)))
    // )
    //
    // WASM function type: (func (param i32 i32 i32) (result i32))
    fd_prestat_dir_name(fd, ptrPath, lengthPath) {
        let fileDescriptor = this.process.fdTable.get(fd);
        if (fileDescriptor === undefined) {
            return errno.badf;
        }
        let [isPreopened, isPreopenedDir, name] = fileDescriptor.file.prestat();
        if (!isPreopened) {
            return errno.badf;
        }
        if (!isPreopenedDir) {
            return errno.badf;
        }
        this.byteArray.subarray(ptrPath, ptrPath + lengthPath).set(name);
        return errno.success;
    }

    // ;;; Terminate the process normally. An exit code of 0 indicates successful
    // ;;; termination of the program. The meanings of other values is dependent on
    // ;;; the environment.
    // (@interface func (export "proc_exit")
    //   ;;; The exit code returned by the process.
    //   (param $rval $exitcode)
    //   (@witx noreturn)
    // )
    //
    // WASM function type: (func (param i32))
    proc_exit() {
        throw new Error("proc_exit not implemented");
    }
}

let system = new WasiSystem();
let busy = false;

async function run() {
    if (busy) {
        throw new Error("benchmark run is already in process");
    }
    busy = true;
    let {module, instance} = await WebAssembly.instantiateStreaming(
        fetch("executable.wasm"),
        system.imports()
    );
    system.exports = instance.exports;
    try {
        instance.exports["_start"].apply(null, []);
        busy = false;
        globalThis.postMessage({"kind": "done"});
    } catch (error) {
        busy = false;
        globalThis.postMessage({"kind": "error", "message": error.toString()});
        throw error;
    }
}

globalThis.addEventListener("message", (event) => {
    if (event.data.kind === "run") {
        run();
    } else {
        console.error("unexpected event kind", event.data.kind);
    }
});
globalThis.addEventListener("messageerror", (_event) => {
    console.error("main thread message could not be deserialized");
});
