# The Silo File-System

1. [Overview](#overview)
2. [Build and Install](#build-and-install)
3. [Preparation](#preparation)
4. [Usage](#usage)
5. [Why Silofs?](#why-silofs)
6. [License](#license)


## Overview

Silofs *("stored in large objects file-system")* is a user-space
file-system for storing large volumes of data as encrypted blobs.
It allows normal users to create an isolated storage area, with its
own private key, and mount it on local host. When mounted users may
manipulate their data as they would do with any other file-system,
while the actual data (and meta-data) is transparently encrypted and
stored within a local repository as opaque blobs. Other processes,
which have the appropriate UNIX credentials, may access those blobs as
regular files, but they can not view their content. This model allows
common Linux utilities such as [rsync](https://rsync.samba.org/) and
[rclone](https://rclone.org/) to backup or archive the content of the
repository into remote location, yet without compromising the integrity
of the underlying data.

Silofs is implemented using Linux's FUSE bridge, and as such it trades
performance with functionality and ease of use. It is designed to serve
those who wish to easily ship media content into external cloud storage
for long-term archiving, but without revealing information on their
private data, and without paying high costs and extra resources due to
re-packing. See [Why Silofs?](#why-silofs) for more details.


## Build and Install

Clone `silofs` source code into local repository from its home at
[github](https://github.com/synarete/silofs). Depending on your system,
you may need to install additional development packages in order to
compile it. On *rpm* or *deb* based systems, an appropriate install
scripts may be found under the *dist* directory in the source tree:

```console
$ git clone https://github.com/synarete/silofs
$ cd silofs

$ # on rpm-based system:
$ sudo dist/rpm/install-rpm-deps.sh

$ # on deb-based system:
$ sudo dist/deb/install-deb-deps.sh
```

Once all build-dependencies are installed on your local build machine,
bootstrap the project and execute the standard GNU/autotools build
process with `configure`, `make` and `make install`:

```console
$ ./bootstrap
$ ./configure --sysconfdir=/etc
$ make
$ sudo make install
```

Alternatively, when running over *rpm* or *deb* based systems, you may
try installation via package managers. Helper scripts are provided to
build packages directly from source:

```console
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
via system wide configuration file at `/etc/silofs/mountd.conf`. As a
security enhancement, only directories which are listed by the host\'s
administrator in this configuration file, and to which the mounting
user have valid access, may be used as mount points for `silofs`.
Whenever adding new entries to this file, the `silofs-mountd.service`
must be restarted for changes to take effect.

The first step after installation, and before mounting any `silofs`
instance, the administrator of the host machine should add new entries
to `silofs-mountd.service` (as a privileged user):

```console
$ echo '/path/to/mntdir' >> /etc/silofs/mountd.conf
$ systemctl restart silofs-mountd.service
$ systemctl enable silofs-mountd.service
```

## Usage

### Format

Silofs stores all user-data and its associate meta-data with special
files called *blobs*, which resides within a special directory
structure called *repository*. There is no limit to the number of
repositories a user may create, or the number of distinct file-system
which are co-located within the same repository, thou a good practice
would be to define a single file-system (with all its associated
snapshots) within a single repository. In order to setup a new silofs
repository over an empty directory, use the `silofs init` command:

```console
$ silofs init /path/to/repo
```

After successful initialization of new repository the user may create
new file-system layout within this repository using the `silofs mkfs`
command. When creating a new file-system the user must provide at least
three fundamental parameters:

  1. A path-name at the repository's root, which hold's a reference
     (by UUID) to the file-system's boot configuration file. This file
     also defines the file-system's name.
  2. A password which is used as input to a key derivation function
     that derive the file-system's main secret key. It is strongly
     recommended to use a unique and strong password.
  3. The capacity-size (in bytes) of the newly formatted file-system.
     This value may be defined in Giga-bytes or Tera-bytes units (using
     the G or T suffix), from 2G up to 64T.

For example, creating a 100G file-system called `myfs` with:

```console
$ silofs mkfs --size=100G /path/to/repo/myfs
enter password: ********
re-enter password: ********
```

### Mount

After the file-system creation completed successfully, it may be
mounted on a valid mount-path, using the `silofs mount` command. In
order to mount it, the user would need to provide the same password
used upon the file-system's creation (by `silofs mkfs`), or else the
mount operation will fail. Note that this user **does not** need to be
a privileged user in order to execute `silofs mount` successfully; the
actual `mount` system call is performed by an auxiliary daemon process
`silofs-mountd.service`, as described in [Preparation](#preparation).
However, to enhanced security the user which executes `silofs mount`
must have read-write access to the mount-point directory:

```console
$ # ensure mounting service is active
$ systemctl status silofs-mountd.service

$ # make me owner of mount-point
$ sudo chown $(id -u):$(id -g) /path/to/mntdir

$ # mount a file-system using daemon process
$ silofs mount /path/to/repo/myfs /path/to/mntdir
enter password: ********

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

Like any other local file-system, silofs serves requests as long as it
is mounted; however, being a FUSE based file system those requests are
executed by ordinary user-space process, so normal users may monitor
its resource utilization using standard command-line tools:

```console
$ top -p $(pgrep -f "silofs mount")

$ du -sh /path/to/repo/
```

When done using this mounted file-system (which may take as long as
needed, from few seconds up to many month of system uptime) the user
may unmount the file-system using the `silofs umount` command. Same
as in the mount case, there is no need for elevated privileges. The
actual `umount` system call is issued by the `silofs-mountd.service`
daemon:

```console
$ silofs lsmnt
/path/to/mntdir
$ silofs umount /path/to/mntdir
```

### Snapshot

A silofs snapshot captures a complete state of the file-system at a
particular point in time, and fossilize it. There are two types of
snapshot operations: *online* and *offline*. The *online* mode operates
on a locally mounted silofs file-system (using dedicated ioctl), while
the *offline* mode manipulates the repository blobs directly. In both
cases, upon successful completion, an identical file-system is formed
within the same repository, but with a different name. This newly
created file-system shares the same blobs as the original file-system
in read-only mode, and performs copy-on-write for every mutating
operation.

Creating an online snapshot requires a mounted `silofs` file-system, in
read-write mode. Upon successful `silofs snap` a new boot configuration
file with the snapshot name is created at the root of the repository:

```console
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

```console
$ silofs umount /path/to/mntdir
$ silofs snap --name=snap2 --offline /path/to/repo/myfs
enter password: ********
...
$ ls /path/to/repo
myfs snap1 snap2
```

In both bases, the newly created snapshot may be mounted as an ordinary
silofs file-system:

```console
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

## Why Silofs?

There are numerous archive and backup tools in the GNU/Linux world,
from the classic *tar* utility to modern complex applications (such as
[restic](https://restic.net), [duplicity](https://duplicity.gitlab.io)
and many more). Most, if not all, use the method of traversing an
existing file-system namespace during their operational cycle and
process every entry along the way. When used as an incremental tools,
they would also need to identify what portions of the namespace has
changed from the previous iteration. However, this approach does not
scale well for very large volumes of data:

  1. Encryption and re-packing an existing volume requires a secondary
     storage space, with roughly the same size as the original data
     set.
  2. The action of detecting *what* changed and re-pack it efficiently
     may become costly, with respect to both memory and CPU utilization
     during archive process.

Both of those problem does not exist for silofs: data is packed from
the very beginning as encrypted blobs in a cloud-friendly format and
therefore there is no need for additional processing or traversal.

As a demonstrative example, consider the following set of changes to a
single file:

```console
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
*step2* represents four simple and relatively lightweight meta-data
operations. However, without hints from the underlying file-system,
many archive tools may be fooled to think that between *step1* and
*step2* a new file was created, thus wasting costly storage space. Even
more sophisticated modern backup applications, which typically use
content addressable mechanism to cope with this problem, fail to
produce optimal results beyond a certain volume size and namespace
complexity.

## License

[GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)

