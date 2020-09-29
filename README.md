# NAME

mwinussh - Manage Windows Users via SSH (MWinUSSH)

# DESCRIPTION

A simple command line program to manage user accounts and sessions
on a Windows machine (Windows 10 tested) via ssh. It was written
when my son's primary computer changed from an iMac to Windows 10.
The program that I wrote to similarly control the iMac is written
in bash, but Windows 10 was a larger lift and needed Perl.  I
named this program mwinussh thinking that I may create and release
an analogous mmacussh at a later date.

# USAGE

Run the program with --help as a command line option to learn
about its command line options and to see examples of usage.

# FILES

Simple "key value" pair configuration files can be used by this
program to save you from having to specify so many command line
arguments. You can instruct the program to use a particular config
file with --conf=&lt;file> and the program will automatically look
for and use any &lt;progname>.conf file that exists in the same
directory with it.

# PREREQUISITES

## PERL MODULES

This program requires these non-core modules:

`IPC::Run` - libipc-run-perl on Ubuntu

## SSH

This program requires the ssh binary and was first developed
using OpenSSH\_7.2p2 on Linux Mint with the ssh binary located
at /usr/bin/ssh. If your ssh binary is in a different location,
set the $SSH\_EXE variable in the code accordingly.

## SSH ID

This program requires you to provide a --sshid file holding an
openssh private key that will be accepted --host for --user in
order to perform its work. The --user must be an Administator
on the Windows --host for this program to function properly.

## WINDOWS SSH CONFIGURATION

There is some information and some ULRs in comments at the top of
the program that may prove helpful in installing and configuring
OpenSSH for Windows 10 in such a way that this program will work.

# AUTHOR

Lester Hightower &lt;hightowe at cpan dot org>

# LICENSE

This program may be distributed under the same terms as Perl itself.

# CHANGELOG

    2030-Sep-29 v1.0 - Initial release.

# TODO

Consider porting to Net::OpenSSH or Net::SSH2.

# OPERATING SYSTEMS AND SCRIPT CATEGORIZATION

## Unix-like
   - Originally written and tested on Linux Mint 18.3.

## SCRIPT CATEGORIES

`UNIX/System_administration`, `Win32/Utilities`
