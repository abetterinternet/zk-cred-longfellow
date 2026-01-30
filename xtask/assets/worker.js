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

class FdStat {
    constructor(fileType, flags, rightsBase, rightsInheriting) {
        this.fileType = fileType;
        this.flags = flags;
        this.rightsBase = rightsBase;
        this.rightsInheriting = rightsInheriting;
    }

    write(pointer) {
        getMemoryDataView().setUint8(pointer, this.fileType);
        getMemoryDataView().setUint16(pointer + 2, this.flags, true);
        getMemoryDataView().setBigUint64(pointer + 8, this.rightsBase, true);
        getMemoryDataView().setBigUint64(pointer + 16, this.rightsInheriting, true);
    }
}

// A virtual file representing stdout or stderr.
class OutputPipe {
    stat() {
        return new FdStat(filetype.character_device, 0, rights.fd_write, 0n);
    }

    writev(ptrIovecArray, lengthIovecArray) {
        let bufferSize = 0;
        for (let i = 0; i < lengthIovecArray; i++) {
            let bufLen = getMemoryDataView().getUint32(ptrIovecArray + i * 8 + 4, true);
            bufferSize += bufLen;
        }

        let buffer = new ArrayBuffer(bufferSize);
        let bufferArray = new Uint8Array(buffer);
        let size = 0;
        for (let i = 0; i < lengthIovecArray; i++) {
            let buf = getMemoryDataView().getUint32(ptrIovecArray + i * 8, true);
            let bufLen = getMemoryDataView().getUint32(ptrIovecArray + i * 8 + 4, true);
            bufferArray.set(getMemoryByteArray().subarray(buf, buf + bufLen), size);
            size += bufLen;
        }

        globalThis.postMessage(
            {
                "kind": "pty_write",
                "buffer": buffer,
            },
            [buffer]
        );

        return size;
    }
}

class FdTable {
    constructor() {
        this.map = new Map();
        this.map.set(1, new OutputPipe());
        this.map.set(2, new OutputPipe());
    }

    get(fd) {
        return this.map.get(fd);
    }
}

let fdTable = new FdTable();

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

let args = new SerializedArgs(["a.out", "--bench"]);

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
function args_sizes_get(ptrNumArgs, ptrDataSize) {
    getMemoryDataView().setUint32(ptrNumArgs, args.offsets.length, true);
    getMemoryDataView().setUint32(ptrDataSize, args.buffer.byteLength, true);
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
function args_get(ptrArgv, ptrArgvBuf) {
    for (let i = 0; i < args.offsets.length; i++) {
        getMemoryDataView().setUint32(
            ptrArgv + i * 4,
            ptrArgvBuf + args.offsets[i],
            true
        );
    }
    getMemoryByteArray().set(new Uint8Array(args.buffer), ptrArgvBuf);
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
function random_get(ptr, len) {
    crypto.getRandomValues(getMemoryByteArray().subarray(ptr, len));
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
function clock_time_get(clockId, _precision, ptrTimestamp) {
    if (clockId == 0) {
        // $realtime
        //
        // This returns a Unix timestamp.
        getMemoryDataView().setBigUint64(
            ptrTimestamp,
            BigInt(Math.round(Date.now() * 1000000)),
            true
        );
        return errno.success;
    } else if (clockId = 1) {
        // $monotonic
        getMemoryDataView().setBigUint64(
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
function fd_read() {
    throw new Error("fd_read not implemented");
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
function fd_write(fd, ptrIovecArray, lengthIovecArray, ptrSize) {
    let file = fdTable.get(fd);
    if (fd === undefined) {
        return errno.badf;
    }
    let size = file.writev(ptrIovecArray, lengthIovecArray);
    getMemoryDataView().setUint32(ptrSize, size, true);
    return errno.success;
}

// ;;; Return the attributes of an open file.
// (@interface func (export "fd_filestat_get")
//   (param $fd $fd)
//   ;;; The buffer where the file's attributes are stored.
//   (result $error (expected $filestat (error $errno)))
// )
//
// WASM function type: (func (param i32 i32) (result i32))
function fd_filestat_get() {
    throw new Error("fd_filestat_get not implemented");
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
function path_create_directory() {
    throw new Error("path_create_directory not implemented");
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
function path_filestat_get() {
    throw new Error("path_filestat_get not implemented");
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
function path_open() {
    throw new Error("path_open not implemented");
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
function fd_readdir() {
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
function environ_get(_ptrEnviron, _ptrEnvironBuf) {
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
function environ_sizes_get(ptrNumVars, ptrDataSize) {
    getMemoryDataView().setUint32(ptrNumVars, 0, true);
    getMemoryDataView().setUint32(ptrDataSize, 0, true);
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
function fd_close() {
    throw new Error("fd_close not implemented");
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
function fd_fdstat_get(fd, ptrStat) {
    let file = fdTable.get(fd);
    if (fd === undefined) {
        return errno.badf;
    }
    file.stat().write(ptrStat);
    return errno.success;
}

// ;;; Return a description of the given preopened file descriptor.
// (@interface func (export "fd_prestat_get")
//   (param $fd $fd)
//   ;;; The buffer where the description is stored.
//   (result $error (expected $prestat (error $errno)))
// )
//
// WASM function type: (func (param i32 i32) (result i32))
function fd_prestat_get() {
    throw new Error("fd_prestat_get not implemented");
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
function fd_prestat_dir_name() {
    throw new Error("fd_prestat_dir_name not implemented");
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
function proc_exit() {
    throw new Error("proc_exit not implemented");
}

const imports = {
    "wasi_snapshot_preview1": {
        "args_sizes_get": args_sizes_get,
        "args_get": args_get,
        "random_get": random_get,
        "clock_time_get": clock_time_get,
        "fd_read": fd_read,
        "fd_write":fd_write ,
        "fd_filestat_get": fd_filestat_get,
        "path_create_directory":path_create_directory ,
        "path_filestat_get": path_filestat_get,
        "path_open": path_open,
        "fd_readdir": fd_readdir,
        "environ_get": environ_get,
        "environ_sizes_get": environ_sizes_get,
        "fd_close": fd_close,
        "fd_fdstat_get": fd_fdstat_get,
        "fd_prestat_get": fd_prestat_get,
        "fd_prestat_dir_name": fd_prestat_dir_name,
        "proc_exit": proc_exit,
    },
};

var exports, dataView, byteArray;

function getMemoryDataView() {
    // Check if the data view has not been initialized yet, or the underlying
    // memory buffer has been detached.
    if (dataView === undefined || dataView.buffer.detached === true) {
        dataView = new DataView(exports.memory.buffer);
    }
    return dataView;
}

function getMemoryByteArray() {
    // Check if the byte array has not been initialized yet, or the memory
    // buffer has been resized.
    if (byteArray === undefined || byteArray.byteLength === 0) {
        byteArray = new Uint8Array(exports.memory.buffer);
    }
    return byteArray;
}

WebAssembly.instantiateStreaming(fetch("executable.wasm"), imports).then(
    ({ module, instance }) => {
        exports = instance.exports;

        instance.exports["_start"].apply(null, []);
    }
).catch(
    (error) => {
        globalThis.postMessage({
            "kind": "error",
            "message": error.toString(),
        });
        throw error;
    }
);
