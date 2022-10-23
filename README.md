# The Silo File-System

1. [Overview](#overview)
2. [Build and Install](#build-and-install)
3. [Preparation](#preparation)
4. [Usage](#usage)
5. [Why Silofs?](#why-silofs)
6. [License](#license)


## Overview

Silofs *("stored in large objects file-system")* is a `GNU/Linux`
utility with unique approach to the problem of archiving large volumes
of data: it implements a fully functional file-system on top of binary
large objects (*blobs*), which serve both for I/O operations and data
packing. Combined with built-in snapshot capabilities, compression and
encryption, users can incrementally archive their data into cloud
friendly format.

Silofs is implemented using Linux's `FUSE` bridge, allowing normal
users to mount an isolated storage area. When mounted, the users can
manipulate their data as they would normally do with any other `POSIX`
file-system. Occasionally, they may take a full file-system snapshot
(online or offline) and pack it as a compressed and encrypted archive.
Following ``UNIX`` philosophy of "make each program do one thing well",
the actual shipment of the archive to the cloud should be made by other
tools (e.g. [rclone](https://rclone.org/)). When needed, at any future
point in time, this archive can be restored and reassembled as fully
functional Silofs file-system on the original host or any other Linux
machine.

Being a `FUSE` based file-system, Silofs trades performance with
functionality and ease of use. It does not intend to replace the high
performance in-kernel file-systems, or any of the numerous backup
solutions, but rather serve as an efficient archive solution for large
volumes of data, which need to be shipped to remote cloud storage.
See [Why Silofs?](#why-silofs) for more details.

## Build and Install

The first step in building `silofs` from source is to clone it from
[Github](https://github.com/synarete/silofs). Depending on your system,
you may need to install additional development packages in order to
compile it. On `rpm` or `deb` based systems, an appropriate install
scripts may be found under the *dist* directory in the source tree:

``` sh
$ git clone https://github.com/synarete/silofs
$ cd silofs

$ # on rpm-based system:
$ sudo dist/install-rpm-deps.sh

$ # on deb-based system:
$ sudo dist/install-deb-deps.sh
```

Once all build-dependencies are installed on your local build machine,
you may bootstrap the project and execute the standard *GNU/autotools*
build process with `configure`, `make` and `make install`. It is
recommended (thou not mandatory) to execute this flow from within the
*build* sub-directory:

``` sh
$ ./bootstrap
$ cd build
$ ../configure
$ make
$ make install
```

Alternatively, when running over `rpm` or `deb` based systems, you may
try installation via package managers. Helper scripts are provided to
build packages directly from source:

``` sh
$ # on rpm-based system:
$ ./dist/rpm/packagize-rpm.sh
$ sudo dnf install ./build/dist/silofs-0*.rpm

$ # on deb-based system:
$ ./dist/rpm/packagize-deb.sh
$ sudo apt install ./build/dist/silofs-0*.deb

$ # verify installation
$ silofs --version
```

## Preparation

Silofs is designed to operate as a non-privileged process. A user can
mount his own isolated file-system, without any need for special
resources or capabilities from the system. However, an appropriate
privilege (Linux: `CAP_SYS_ADMIN`) is still required in order to mount
each `silofs` instance. A dedicated mounting daemon service, called
`silofs-mountd.service`, is installed on the host machine and tuned
via system wide configuration file `/etc/silofs/mountd.conf`. As a
security enhancement, only directories which are listed by the host\'s
administrator in this configuration file, and to which the mounting
user have valid access, may be used as mount points for `silofs`.
Whenever adding new entries to this file, the `silofs-mountd.service`
must be restarted for changes to take effect.

The first step after installation, and before mounting any `Silofs`
file-system, should be to add new entries to `silofs-mountd.service`:

``` sh
$ echo '/path/to/mntdir' >> /etc/silofs/mountd.conf
$ sudo systemctl restart silofs-mountd.service
$ sudo systemctl enable silofs-mountd.service
```

## Usage

### Format

Silofs stores all user-data and its associate meta-data with special
files called *blobs*. Those files resides within a special directory
structure called *repository*. There is no limit to the number of
repositories a user may create, or the number of distinct file-system
which are co-located within the same repository, thou a good practice
would be to define a single file-system (with all its associated
snapshots) within a single repository:

``` sh
$ silofs init /path/to/repo
```

After successful initialization of new repository the user may create
new file-system layout within this repository using the `silofs mkfs`
sub command. The name of the file system is defined by the boot
configuration file-name within the root directory of the repository.
The capacity-size (in bytes) of the newly formatted file-system may be
defined in Giga-bytes or Tera-bytes units (using the `G` or `T` suffix)
within the range of `[2G..64T]`. For example, creating a `100G`
file-system called `myfs` with:

``` sh
$ silofs mkfs --size=100G /path/to/repo/myfs
```

### Mount

After the file-system creation completed successfully, it may be mounted
on a valid mount-path, using the `silofs mount` sub command. Note that
you **do not** need to be a privileged user to execute this command; the
actual `mount` system call is performed by an auxiliary
`silofs-mountd.service` daemon, as described in [Preparation](#preparation):

``` sh
$ # ensure mounting service is alive
$ systemctl status silofs-mountd.service

$ # mount a file-system using daemon process
$ silofs mount /path/to/repo/myfs /path/to/mntdir

$ # probe mount-point using silofs command line
$ silofs lsmnt
/path/to/mntdir
$ silofs show boot /path/to/mntdir
/path/to/repo/myfs

$ # probe mount-point using coreutils
$ df -h /path/to/mntdir | tail -n +2
silofs          100G  836K  100G   1% /path/to/mntdir
$ stat -c "%i" /path/to/mntdir
1

$ # do some I/O
$ echo "hello, world" > /path/to/mntdir/hello
$ cat /path/to/mntdir/hello
hello, world
```

Like any other local file-system, Silofs serves requests as long as it
is mounted. However, being a `FUSE` based file system you can also
monitor its resource utilization using standard command-line tools:

``` sh
$ top -p $(pgrep -f "silofs mount")

$ du -sh /path/to/repo/
```

When done using this mounted file-system (which may take as long as
needed, from few seconds up to many month of system uptime) the user may
unmount the file-system using the `silofs umount` sub-command. Same as
in the mount case, there is no need for elevated privileges. The actual
`umount` system call is issued by the `silofs-mountd.service` daemon:

``` sh
$ silofs lsmnt
/path/to/mntdir
$ silofs umount /path/to/mntdir
```

### Snapshot

A Silofs snapshot serves as a fundamental building block in the
archive process. It captures a complete state of the file-system at a
particular point in time, and fossilize it. There are two types of
snapshot operations: *online* and *offline*. The *online* mode operates
on a locally mounted Silofs file-system (using dedicated ioctl), while
the *offline* mode manipulates the repository blobs directly. In both
cases, upon successful completion, an identical file-system is formed
within the same repository, but with a different name. This newly
created file-system shares the same blobs as the original file-system
in read-only mode, and performs copy-on-write for every mutating
operation.

Creating an online snapshot requires a mounted `silofs` file-system, in
read-write mode. Upon successful `silofs snap` a new boot configuration
file with the snapshot name is created at the root of the repository:

``` sh
$ silofs mount /path/to/repo/myfs /path/to/mntdir
$ silofs lsmnt
/path/to/mntdir
$ silofs show boot /path/to/mntdir
/path/to/repo/myfs

$ silofs snap --name=snap1 /path/to/mntdir
$ ls /path/to/repo
myfs snap1
```

Alternatively, the user may achieve the same result using *offline*
mode:

``` sh
$ silofs umount /path/to/mntdir
$ silofs snap --name=snap2 --offline /path/to/repo/myfs
$ ls /path/to/repo
myfs snap1 snap2
```

In both bases, the newly created snapshot may be mounted as an ordinary
`Silofs` file-system:

``` sh
$ silofs mount /path/to/repo/snap2 /path/to/mntdir
$ silofs lsmnt
/path/to/mntdir
$ # read previously written file
$ cat /path/to/mntdir/hello
hello, world
$ # overwrite existing file, triggers copy-on-write
$ echo "hello, world2" > /path/to/mntdir/hello
$ cat /path/to/mntdir/hello
hello, world2
```

### Archive

The Silofs functionality which has been presented so far is what one
would expect from any descent `POSIX` file-system (with the exception of
writable snapshots which are not that common in the Linux world).
However, what makes Silofs different is the way in which it performs
archive (and restore) into (and from) blobs representation.

Under the hood, any Silofs file-system is represented by a set of raw
blobs. The process of archiving is a simply a transformation of one set
of raw blobs into another set of compressed and encrypted blobs.
However, those new blobs are not stored within the same repository as
the original blobs, but rather in a newly created repository, which is
marked with *attic* mode. As the process of archiving also encrypts the
target blobs, the user needs to provide a secure password. The password
itself is **never** stored within the repository so it is very important
to remember or store it in a secure place:

``` sh
$ silofs init --attic /path/to/attic
$ silofs archive /path/to/repo/myfs /path/to/attic/myfs-archive
enter password: ********
re-enter password: ********
...
$ silofs archive /path/to/repo/snap1 /path/to/attic/snap1-archive
enter password: ********
re-enter password: ********
...
$ silofs archive /path/to/repo/snap2 /path/to/attic/snap2-archive
enter password: ********
re-enter password: ********
...
```

Note the in the last example we archived the main file-system as well as
its snapshots. When using the same password for all archive operations
only the difference blobs between each snapshot are added to the attic
repository.

Another observation is that the attic repository does not need to share
the same underlying file-system as the source repository, or even the
same physical block device. Indeed, using different storage device for
source and attic repositories may reduce the overall risk of losing data
in case of hardware failure.

After the archive process has completed (which make take some time,
depending on your data size and local hardware performance), users may
safely ship the entire attic repository onto a different host (e.g.,
using `rsync`) or to remote cloud provider (e.g., using `rclone`). There
is not need to worry about possible security breach, as all the blobs
are fully encrypted.

### Restore

Restore is the complementary operation of archive: transform a
(previously archived) set of compressed-and-encrypted blobs from attic
repository into their original Silofs file-system raw format. A user
may need to restore data for various reasons, such as physical hardware
failure, or using a different host machine. The `silofs restore`
operation requires source archive, located within *attic* repository,
and target raw repository on which the file-system\'s blobs are
reconstructed. The user would also need to provide the password used
upon archive creation so that Silofs would be able to decrypt and
decompress the archived blobs. In the following example data is restored
into newly created (empty) repository, but it may very well operate on
existing repository:

``` sh
$ silofs init /path/to/repo2
$ silofs restore /path/to/attic/myfs-archive /path/to/repo2/myfs
enter password: ********
...
$ silofs mount /path/to/repo2/myfs /path/to/mntdir
$ silofs lsmnt
/path/to/mntdir
```

## Why Silofs?

There are numerous archive and backup tools in the `GNU/Linux` world,
from the classic `tar` utility to modern complex applications (such as
[restic](https://restic.net), [duplicity](https://duplicity.gitlab.io)
and many more). Most, if not all, use the method of traversing an
existing file-system namespace during their operational cycle and
process every entry along the way. When used as an incremental tools,
they would also need to identify what portions of the namespace has
changed from the previous iteration. However, this approach does not
scale well for very large volumes of data. The action of detecting what
changed and re-pack it efficiently may become costly, with respect to
both resource utilization during archive process as well as the final
archive size. As the capacity of modern storage devices increase to the
scale of many terabytes, the solution to this problem requires different
approach.

As a demonstrative example, consider the following set of changes to a
single file:

``` sh
$ # step1: create 1G file with random data
$ dd if=/dev/urandom of=./a bs=1M count=1024
$ stat -c "%h %s" ./a
1 1073741824

$ # step2: change the file's content with meta-data operations
$ truncate --size=2G ./a
$ fallocate --punch-hole --offset=4K --length=1M ./a
$ mv ./a ./b
$ ln ./b ./c
$ stat -c "%h %s" ./b
2 2147483648
```

From the file-system\'s perspective, the sequence of operations in
`step2` represents four simple and relatively lightweight meta-data
operations. However, without hints from the underlying file-system, many
archive tools may be fooled to think that between `step1` and `step2` a
new file was created, thus wasting costly storage space. Even more
sophisticated modern backup applications, which typically use content
addressable mechanism to cope with this problem, fail to produce optimal
results beyond a certain volume size and namespace complexity.

Compared to those tools, Silofs does not need any special hints, as it
implements the file-system itself, using cloud friendly meta-data
format, which has been designed from the ground up for the particular
use-case of archiving. Combined with its native snapshots capabilities,
compression and encryption, the task of archive and restore efficiently
large volumes of data becomes trivial.

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)

