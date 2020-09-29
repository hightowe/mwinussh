#!/usr/bin/perl

##############################################################################
# A program to enable/disable Windows users and to manage login sessions by
# way of ssh. This program was originally written to allow me to control
# computer time for my kids. To end computer time, you'll want to first
# disable the account and then disconnect or logoff any active sessions.
# You can give advance notice of that action my using the message command,
# which is nice if it is being done from a cron job.
#
# This program is now developed and tested on Windows 10 Pro Version 2004,
# running the stock OpenSSH server with public key authentication enabled
# for members of the Admininstrators group. The default shell is cmd.exe
# but I believe that powershell.exe would work fine as well.
#
# Critical fact:
# Note that if the user belongs to the administrator group,
#    %programdata%/ssh/administrators_authorized_keys is used instead.
#
# Potentially helpful guides for setting up OpenSSH on Windows 10:
# - https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
# - https://www.concurrency.com/blog/may-2019/key-based-authentication-for-openssh-on-windows
# - https://docs.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration
#
# Written 2017-2020, by Lester Hightower
##############################################################################

use strict;                                   # core
use version;                                  # core
use diagnostics;                              # core
use Data::Dumper;                             # core
use File::Basename;                           # core
use Cwd 'abs_path';                           # core
use Getopt::Long;                             # core
use IPC::Run 'run';                           # libipc-run-perl

# Application name and version
my $APP_NAME = basename($0);  $APP_NAME =~ s/\.(pl|exe)$//;
my $VERSION = "1.0";
my $SSH_EXE = '/usr/bin/ssh';

my $opts = MyGetOpts(); # Will only return with options we think we can use

# Gather current statuses because they are always required...
my %statuses = ();
($statuses{sessions}, $statuses{sessionsT}) = GetSessions($opts);
($statuses{accounts}, $statuses{accountsT}) = GetAccountStatuses($opts);
#print Dumper(\%statuses) . "\n";

# Take the requested actions
take_actions($opts, \%statuses);

exit;

##############################################################################
##############################################################################
##############################################################################

sub get_ssh_cmd {
  my $opts = shift @_;
  my $cmd = shift @_;
  my @cmd = ($SSH_EXE,'-i',$opts->{sshid},'-oForwardX11=no',);
  if (! ($opts->{sshnobatch})) { push @cmd, '-oBatchMode=yes'; }
  push @cmd, ($opts->{sshuser}.'@'.$opts->{host}, $cmd);
  return @cmd;
}

sub take_actions {
  my $opts = shift @_;
  my $statuses = shift @_;

  # HANDLE status
  if (length($opts->{status})) { print get_printable_status($statuses); }

  # HANDLE message
  if (length($opts->{message})) {
    my $msg = $opts->{message};
    my $cmd = "msg \"$opts->{user}\"";
    my @cmd = get_ssh_cmd($opts, $cmd);
    run \@cmd, '<', \$msg, '>', \my $stdout, '2>', \my $stderr;
    if ($? >> 8) { die "ssh command failed:\n$stderr"; }
    #print $stdout;
  }

  # HANDLE enable/disable
  if ($opts->{enable} || $opts->{disable}) {
    if (! defined($statuses{accounts}->{$opts->{user}})) {
      print "No account found for --user=\"$opts->{user}\" to --enable/--disable.\n";
      exit -1;
    }
  }
  my $activate = undef;
  if ($opts->{enable}) {
    if ($statuses{accounts}->{$opts->{user}}->{Disabled} eq 'FALSE') {
      print "Account for user $opts->{user} is already enabled\n";
    } else {
      print "Enabling account for user $opts->{user}\n";
      $activate = "yes";
    }
  } elsif ($opts->{disable}) {
    if ($statuses{accounts}->{$opts->{user}}->{Disabled} eq 'TRUE') {
      print "Account for user $opts->{user} is already disabled\n";
    } else {
      print "Disabling account for user $opts->{user}\n";
      $activate = "no";
    }
  }
  if (defined($activate)) {
    my $cmd = '';
    my @cmd = ();
    my $stdout = undef;
    my $stderr = undef;

    # Do the enable or disable
    $cmd = "net user \"$opts->{user}\" /active:$activate";
    @cmd = get_ssh_cmd($opts, $cmd);
    run \@cmd, '>', \$stdout, '2>', \$stderr;
    if ($? >> 8) { die "ssh command failed:\n$stderr"; }
    #print $stdout;

    # For enable/disable, we need to find and kill (restart) the LoginUI.exe process that
    # is running on the console, so the username will disappear or reappear in the Windows
    # login screen. The second item in the CSV list is the PID.
    # C:\>tasklist /FO CSV | findstr /I logonui.exe | findstr Console
    # "LogonUI.exe","3256","Console","19","62,656 K"
    print "Trying to kill the Console's LoginUI.exe process...\n";
    $cmd = "tasklist /FO CSV | findstr /I logonui.exe | findstr Console";
    @cmd = get_ssh_cmd($opts, $cmd);
    run \@cmd, '>', \$stdout, '2>', \$stderr;
    if ($? >> 8) { die "ssh command failed:\n$stderr"; }
    if ($stdout =~ m/"LogonUI.exe","([0-9]+)","Console"/i) {
      my $LoginUIpid = $1;
      $cmd = "taskkill /PID \"$LoginUIpid\" /F /T";
      @cmd = get_ssh_cmd($opts, $cmd);
      run \@cmd, '>', \$stdout, '2>', \$stderr;
      if ($? >> 8) { die "ssh command failed:\n$stderr"; }
    }
  }

  # HANDLE disconnect and logoff
  # The order here is important in case the user specifies both.
  # You can logoff a disconnected session but obviously can't
  # disconnect one that was logged off (as it no longer exists).
  foreach my $action (qw(disconnect logoff)) {
    if ($opts->{$action}) {
      if (defined($statuses{sessions}->{$opts->{user}})) {
        my $state = $statuses{sessions}->{$opts->{user}}->{STATE};
        my $sessid = $statuses{sessions}->{$opts->{user}}->{ID};
        my $cmd = undef;
        if ($action eq 'disconnect') { $cmd = "tsdiscon $sessid"; }
        if ($action eq 'logoff')     { $cmd = "logoff $sessid"; }
        if (! defined($cmd)) { die "This code should be unreachable!" }
        print "Doing $action user $opts->{user}, session $sessid, state $state\n";
        my @cmd = get_ssh_cmd($opts, $cmd);
        run \@cmd, '>', \my $stdout, '2>', \my $stderr;
        if ($? >> 8) { die "ssh command failed:\n$stderr"; }
        #print $stdout;
      } else {
        print "No sessions found for --user=\"$opts->{user}\" to --$action\n";
        exit -1;
      }
    }
  }
}

sub get_printable_status {
  my $statuses = shift @_;
  my $t = "ACCOUNTS\n" .
          "--------\n" . $statuses->{accountsT} . "\n" .
          "\n" .
          "SESSIONS\n" .
          "--------\n" . $statuses->{sessionsT} . "\n" .
          "";
  return $t;
}

sub MyGetOpts {
  my %opts=();
  my $result = &GetOptions(\%opts, "help", "h", "version", "status",
			"sshnobatch", "sshuser=s", "sshid=s",
			"enable", "disable", "logoff", "disconnect",
			"host=s", "message=s", "user=s", "conf=s", );
  # If GetOptions complained or user gave no options, exit
  if ((!int($result)) || scalar(keys %opts) == 0) {
    print "\nUse --help for usage message.\n"; exit 0;
  }
  # If the user asked for version, give it and exit
  if ($opts{version}) {
    print "$APP_NAME version $VERSION\n"; exit 0;
  }
  # If the user asked for help, give it and exit
  if ($opts{help} || $opts{h}) {
    print GetUsageMessage(); exit 0;
  }

  my @errs=(); # An array to collect option errors

  # Set any strings that are not defined
  for my $to_define (qw(user message host sshuser sshid conf)) {
    if (! defined($opts{$to_define})) { $opts{$to_define}=''; }
  }

  # Set any booleans that are not defined
  for my $to_define (qw(sshnobatch disconnect logoff disable enable)) {
    if (! defined($opts{$to_define})) { $opts{$to_define} = 0; }
  }

  # Load config file options. The way this works is that any
  # strings from %opts that are defined but zero length will
  # be replaced by any found in the config file.
  my %conf=();
  if (length($opts{conf}) && (! -e -f -r $opts{conf})) {
    push @errs, "Config file from --conf is missing or unreadable.";
  } else {
    # If given, we use the file specified in --conf and fall back to
    # "$APP_NAME.conf" in the same path as this program, if it exists.
    my @conf_files = ();
    push @conf_files, $opts{conf} if length($opts{conf});
    push @conf_files, dirname(abs_path($0)) . "/$APP_NAME.conf";
    CONF_FILE: foreach my $conf_file (@conf_files) {
      if (-e -f -r $conf_file) {
        my $conf_data = file_slurp($conf_file);
        my @lines = split /^/, $conf_data;
        @lines = map { $_=~s/[\r\n]//g; $_; } @lines; # chomp lines
        @lines = grep(!/^$/, @lines);                 # remove blank lines
        @lines = grep(!/^\s*#/, @lines);              # remove comment lines
        foreach my $line (@lines) {
          my ($k, $v) = split(/\s+/, trim($line), 2);
          $conf{$k} = $v;
        }
        last CONF_FILE; # Stop at the first one found
      }
    }
  }
  # If we loaded any %conf options, put them into %opts for any
  # options that are not already set.
  foreach my $key (keys %conf) {
    # By testing for "defined($opts{$key})" we will silently
    # ignore any invalid %conf options.
    if (defined($opts{$key}) && (! length($opts{$key}))) {
      $opts{$key} = $conf{$key};
    }
  }

  # Validate the always required string parameters
  foreach my $useropt (sort qw(host sshuser sshid)) {
    if (! length($opts{$useropt})) {
      push @errs, "Parameter --$useropt=<str> is required.";
    }
  }

  # Validate the options that require --user to be set
  foreach my $useropt (sort qw(message enable disable logoff disconnect)) {
    if ($opts{$useropt} && (! length($opts{user}))) {
      push @errs, "Must specify --user=<str> for --" . $useropt;
    }
  }

  if ($opts{enable} && $opts{disable}) {
    push @errs, "Cannot both --enable and --disable";
  }

  if (! (-f -r $opts{sshid})) {
    push @errs, "--sshid does not exist or is unreadable: $opts{sshid}";
  }

  # We lowercase all usernames in this program
  $opts{user} = lc($opts{user});

  # If there were errors, report them
  if (scalar(@errs)) {
    print "There were errors:\n" .  "  " . join("\n  ", @errs) . "\n\n";
    print "Use --help for usage message.\n";
    exit;
  }

  return \%opts;
}

sub GetUsageMessage() {
  my $parmlen = 13;
  my $col1len = $parmlen + 3;
  my @params = (
    [ host       => 'The host to operate on. (required)' ],
    [ sshuser    => 'The ssh username to use. (required)' ],
    [ sshid      => 'The password-less ssh ID (private key) to use. (required)' ],
    [ user       => 'The user to operate on. (often required)' ],
    [ status     => 'Show statuses of account(s) and session(s).' ],
    [ message    => 'Send this message to the --user.' ],
    [ enable     => 'Enable the --user account.' ],
    [ disable    => 'Disable the --user account.' ],
    [ disconnect => 'Disconnect a session for the --user account.' ],
    [ logoff     => 'Logoff a session for the --user account.' ],
    [ conf       => "A config file that can hold some of these values. The\n" .
                    " "x$col1len .
                    "default is $APP_NAME.conf in the directory with this program." ],
    [ sshnobatch => "Don't set ssh -oBatchMode=yes, to allow password logins." ],
    [ version    => 'Display program version.' ],
    [ help       => 'This message.' ],
  );
  my $t="Usage: $APP_NAME --host=<host> --user=<user> ...\n\n";
  foreach my $param (@params) {
    $t .= sprintf("  %-13s %s\n", '--'.$param->[0], $param->[1]);
  }
  $t .= "\n";
  $t .= "Examples:\n" .
	" $APP_NAME --conf=kidspc.conf --status\n" .
	" $APP_NAME --conf=kidspc.conf --status --user=tommy\n" .
	" $APP_NAME --conf=kidspc.conf --disable --disconnect --user=sally\n" .
	" $APP_NAME --conf=tommmy.conf --message='Computer time ends in 10 minutes. - Dad'\n" .
	"";

  return $t;
}

sub GetAccountStatuses {
  my $opts = shift @_;

  my $where_clause="";
  if ( length($opts->{user}) ) {
    $where_clause = "where name='$opts->{user}' ";
  }

  # Get user account statuses
  my $cmd = "wmic useraccount $where_clause" .
		"get Name,Lockout,Disabled,PasswordExpires,PasswordRequired";
  my @cmd = get_ssh_cmd($opts, $cmd);
  # We capture stderr here because "No Instance(s) Available." is printed there
  # by wmic if no account exist for a specific user that we queried for.
  run \@cmd, '>', \my $stdout, '2>', \my $stderr;
  if ($? >> 8) { die "ssh command failed:\n$stderr"; }
  #print "LHHD:\n$stdout\n\n$stderr\n";
  my @lines = split /^/, $stdout;
  @lines = map { $_=~s/[\r\n]//g; $_; } @lines; # chomp lines
  @lines = grep(!/^$/, @lines);                 # remove blank lines
  if (! scalar(@lines)) { return ({}, ''); }    # No results
  my %ActStatuses = ();
  my @hdrs = split(/\s+/, $lines[0]);
  foreach my $l (1..$#lines) {
    if (!length($lines[$l])) { next; } # skip blank lines
    my @data = split(/\s+/, $lines[$l]);
    if (scalar(@data) == scalar(@hdrs)) {
      my %d = ();
      foreach my $i (0..$#hdrs) {
	$d{$hdrs[$i]} = $data[$i];
      }
      # We lowercase all usernames in this program
      $d{Name} = lc($d{Name});
      $ActStatuses{$d{Name}} = \%d;
    }
  }

  #print Dumper(\@hdrs, \@lines, \%ActStatuses) . "\n";
  #print Dumper(\%ActStatuses) . "\n";
  return (\%ActStatuses, join("\n", @lines));
}

sub GetSessions {
  my $opts = shift @_;

  # Settled on quser; qwinsta/"query session" was considered.
  my $cmd = "quser";
  if ( length($opts->{user}) ) {
    $cmd .= ' "' . $opts->{user} . '"';
  }
  my @cmd = get_ssh_cmd($opts, $cmd);
  # We capture stderr here because "No User exists for foo" is printed there
  # by quser if no sessions exist for a specific user that we queried for.
  # Also note that quser exits with "1" in the "No User exists" case and
  # that gets passed back to us here, which is why we accept it.
  run \@cmd, '>', \my $stdout, '2>', \my $stderr;
  my $exit_code = $? >> 8;
  if ($exit_code != 0 && $exit_code != 1) { die "ssh command failed:\n$stderr"; }
  #print "LHHD:\n$stdout\n\n$stderr\n";
  my @lines = split /^/, $stdout;
  @lines = map { $_=~s/[\r\n]//g; $_=~s/^.//; $_; } @lines;
  if (! scalar(@lines)) { return ({}, ''); }    # No results
  # USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
  my @hdrs = $lines[0] =~ m/^(USERNAME)(\s+)(SESSIONNAME)(\s+)(ID)(\s+)(STATE)(\s+)(IDLE TIME)(\s+)(LOGON TIME)(\s*)$/;
  my %hdr_lens = @hdrs; # Makes a hash w/k=header and v=trailing spaces
  @hdrs = grep(!/^\s*$/, @hdrs); # Reduce the @hdrs array to just the headers
  # Change %hdr_lens values to the number of trailing spaces (ints)
  foreach my $hdr (keys %hdr_lens) {
    $hdr_lens{$hdr} = length($hdr) + length($hdr_lens{$hdr}) - 1;
  }
  # Build %data_pos to hold the start/end positions for each data field
  my %data_pos = ();
  my $pos = 0;
  foreach my $hdr (@hdrs) {
    $data_pos{$hdr}->{start} = $pos;
    $data_pos{$hdr}->{end} = $pos + $hdr_lens{$hdr};
    if ($hdr eq 'LOGON TIME') { $data_pos{$hdr}->{end} = $pos + 20; } # May be too long
    $pos = $data_pos{$hdr}->{end} + 1;
  }
  #print Dumper(\@hdrs, \%hdr_lens, \%data_pos) . "\n";

  # Use @hdrs and %data_pos to parse each line of data and populate %ActStatuses
  my %ActStatuses = ();
  foreach my $l (1..$#lines) {
    if (!length($lines[$l])) { next; } # skip blank lines
    my %d = ();
    foreach my $hdr (@hdrs) {
      my $s = $data_pos{$hdr}->{start};
      my $e = $data_pos{$hdr}->{end};
      $d{$hdr} = trim(substr($lines[$l], $s, $e - $s));
    }
    # We lowercase all usernames in this program
    $d{USERNAME} = lc($d{USERNAME});
    $ActStatuses{$d{USERNAME}} = \%d;
  }

  #print Dumper(\@hdrs, \@lines, \%ActStatuses) . "\n";
  #print Dumper(\%ActStatuses) . "\n";
  return (\%ActStatuses, join("\n", @lines));
}

sub trim($) {
  my $str = shift @_;
  $str =~ s/^\s+//g;  $str =~ s/\s+$//g;
  return $str;
}

sub file_slurp {
  my $file = shift;
  open my $fh, '<', $file or die;
  local $/ = undef;
  my $cont = <$fh>;
  close $fh;
  return $cont;
}

########################################################################
# POD ##################################################################
########################################################################

=head1 NAME

mwinussh - Manage Windows Users via SSH (MWinUSSH)

=head1 DESCRIPTION

A simple command line program to manage user accounts and sessions
on a Windows machine (Windows 10 tested) via ssh. It was written
when my son's primary computer changed from an iMac to Windows 10.
The program that I wrote to similarly control the iMac is written
in bash, but Windows 10 was a larger lift and needed Perl.  I
named this program mwinussh thinking that I may create and release
an analogous mmacussh at a later date.

=head1 USAGE

Run the program with --help as a command line option to learn
about its command line options and to see examples of usage.

=head1 FILES

Simple "key value" pair configuration files can be used by this
program to save you from having to specify so many command line
arguments. You can instruct the program to use a particular config
file with --conf=<file> and the program will automatically look
for and use any <progname>.conf file that exists in the same
directory with it.

=head1 PREREQUISITES

=head2 PERL MODULES

This program requires these non-core modules:

C<IPC::Run> - libipc-run-perl on Ubuntu

=head2 SSH

This program requires the ssh binary and was first developed
using OpenSSH_7.2p2 on Linux Mint with the ssh binary located
at /usr/bin/ssh. If your ssh binary is in a different location,
set the $SSH_EXE variable in the code accordingly.

=head2 SSH ID

This program requires you to provide a --sshid file holding an
openssh private key that will be accepted --host for --user in
order to perform its work. The --user must be an Administator
on the Windows --host for this program to function properly.

=head2 WINDOWS SSH CONFIGURATION

There is some information and some ULRs in comments at the top of
the program that may prove helpful in installing and configuring
OpenSSH for Windows 10 in such a way that this program will work.

=head1 AUTHOR

Lester Hightower <hightowe at cpan dot org>

=head1 LICENSE

This program may be distributed under the same terms as Perl itself.

=head1 CHANGELOG

 2030-Sep-29 v1.0 - Initial release.

=head1 TODO

Consider porting to Net::OpenSSH or Net::SSH2.

=head1 OPERATING SYSTEMS AND SCRIPT CATEGORIZATION

=pod OSNAMES

=head2 Unix-like
   - Originally written and tested on Linux Mint 18.3.

=head2 SCRIPT CATEGORIES

=pod SCRIPT CATEGORIES

C<UNIX/System_administration>, C<Win32/Utilities>

