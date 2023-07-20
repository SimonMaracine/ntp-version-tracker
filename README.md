# ntp-version-tracker

<!-- TODO needs updating -->

It is a program made for the Linux router `I-O DATA WN-AC1167GR`, for reporting vulnerable versions
of the `NTP` protocol, by logging useful information.

## Purpose

For security, detect IoT devices that use old and vulnerable versions of `NTP`.

## Requirements

* A CLI program with commands and options, as needed
* Use of the `pcap` API for capturing packets and reading save files
* Parsing `Ethernet`, `IP`, `UDP` and `NTP` headers
* Detecting `NTP` packets and reporting the versions
* Applying filters
* Logging of information in the console and in a file
* Graceful exiting and handling of errors
* Written in the C programming language
* Use of a special SDK for compiling for the target router architecture

## Solutions and Implementation

Two versions can be built. One for the `I-O DATA WN-AC1167GR` router and another for
any Linux machine. The latter is for development testing purposes and is built by invoking:

```sh
make local_ntp_version_tracker
```

The program makes extensive use of the C standard library for accomplishing its tasks. Also,
additional system and third-party libraries are utilized: `pcap`, `pthread` and `jansson`
respectively.

`jansson` is included as a git submodule, but it needs to be built and installed in the system
separately from the program. `install_jansson.sh` helper script is for this purpose.

---

For parsing command line arguments, the C function `getopt` is used. Four commands are implemented:

* `-d` for capturing packets on a network interface
* `-f` for reading save files (previous captures)
* Of course, `-h` and `-v` for a nice command line interface

Also, lots of options are available. They can alter the behavior of the program, making it more
versatille. Run

```sh
ntp_version_tracker -h
```

to see a list of all of them.

---

Live capturing of packets uses a **non-blocking** mechanism together with `pselect`.

Reading save files is more straight forward.

---

For logging various formatted messages, the `vfprintf` function is used.

One very important problem is the amount of logging that could be done. Routers usually have
limited amount of main memory. That's why there exists an option for specifying the maximum amount
of bytes that can be written to the console and file. If that amount is exceeded, the program
automatically terminates in a graceful manner.

---

The code is written in such a way that it's clear from the function and symbol names were in the
codebase they belong to. This is to combat the **lack of namespaces** in C.

Global variables are used only in appropriate places and even so, they are internal to their
respective compilation units.

Error handling is done rigorously to minimze unexpected behavior; even memory allocation calls with
`malloc` are handled.

---

The processing of packets is done in two layers:

1. In a callback function passed to `pcap`, which parses and checks the protocols the packet
   contains.
2. In an another callback function, written in the high-level part of the codebase, which executes
   actions depending on certain conditions, like which headers are available.

Right now, the second callback function just reports the `NTP` versions.

---

Optionally, data can be periodically exported into the `JSON` format. This is done in a separate
**thread**, as exporting can be done at any point, not only at shutdown time and IO operations can
take time. Right now, data is only exported to the disk, but it could just as well be transmitted
over the network.

To facilitate the inter-thread communication, an **atomic queue** is used. Luckily, the requirements
aren't hard to achieve. In short, the main thread puts data onto the queue and the exporting thread
only takes data off from the queue.

This functionality is only available when capturing packets live.

<!-- TODO write about profiling -->
