#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0-only
# TACACS+ login on NuDanOS: pam_tacplus and nss_tacplus read servers and
# secrets from a root-only /etc/tacplus_servers; mapped accounts tacacsN get
# the groups of a DANOS level.
use strict;
use warnings;
use File::Temp qw(tempdir);
use Test::More;
use lib 'lib';
use Vyatta::Login::TacplusLogin qw(servers_file_content level_groups write_private_file);

my $content = servers_file_content(
    [ { address => '10.0.2.2', port => 49, secret => 'nudanos-tac-1' },
      { address => '2001:db8::1', port => 4949, secret => 'other' } ], 7);
like( $content, qr/^secret=nudanos-tac-1\nserver=10\.0\.2\.2:49\n/m, 'secret precedes its server' );
like( $content, qr/^secret=other\nserver=\[2001:db8::1\]:4949\n/m, 'IPv6 server in brackets' );
like( $content, qr/^timeout=7$/m, 'timeout' );
is( servers_file_content([], 7), '', 'no servers, empty file' );

my $dir = tempdir( CLEANUP => 1 );
open my $fh, '>', "$dir/level" or die;
print $fh "superuser:vyattacfg,routeadm,vyattasu,adm,wireshark,systemd-journal\n",
          "admin:vyattacfg,routeadm,vyattaadm,adm,wireshark,systemd-journal\n",
          "operator:vyattaop,routeadm,wireshark,systemd-journal\n";
close $fh;
is_deeply( [ level_groups( 'admin', "$dir/level" ) ],
    [qw(vyattacfg routeadm vyattaadm adm wireshark systemd-journal)], 'admin groups' );
is_deeply( [ level_groups( 'operator', "$dir/level" ) ],
    [qw(vyattaop routeadm wireshark systemd-journal)], 'operator groups' );
is_deeply( [ level_groups( 'nosuch', "$dir/level" ) ], [], 'unknown level, no groups' );

write_private_file( "$dir/tacplus_servers", "secret=x\n" );
is( ( stat "$dir/tacplus_servers" )[2] & 07777, 0600, 'servers file is root-only (0600)' );
open my $in, '<', "$dir/tacplus_servers" or die;
is( do { local $/; <$in> }, "secret=x\n", 'content written' );
done_testing();
