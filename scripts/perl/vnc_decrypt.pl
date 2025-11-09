#!/usr/bin/perl
use strict;
use warnings;
use Crypt::DES;

if (@ARGV != 1) {
    print "Usage: $0 <encrypted_hex>\n";
    exit 1;
}

my $encrypted_hex = $ARGV[0];
$encrypted_hex =~ s/\s+//g;

if ($encrypted_hex !~ /^[0-9a-fA-F]+$/) {
    print "Error: Invalid hex format.\n";
    exit 1;
}

# Handle different hex lengths for UltraVNC
if (length($encrypted_hex) > 16) {
    $encrypted_hex = substr($encrypted_hex, 0, 16);
    print "Truncated to 8 bytes: $encrypted_hex\n";
} elsif (length($encrypted_hex) < 16) {
    $encrypted_hex .= "0" x (16 - length($encrypted_hex));
    print "Padded to 8 bytes: $encrypted_hex\n";
}

# Try different VNC implementations
my @keys = (
    pack("H*", "e84ad660c4721ae0"),  # Standard VNC
    pack("H*", "175266062e5e5807"),  # Alternative VNC
    pack("C*", 0x17, 0x52, 0x6b, 0x06, 0x23, 0x4e, 0x58, 0x07),  # Raw bytes
    pack("C*", 0x23, 0x82, 0x10, 0x7d, 0x43, 0xa8, 0x48, 0xe2),  # UltraVNC variant
);

my $encrypted_bytes = pack("H*", $encrypted_hex);

foreach my $key (@keys) {
    eval {
        my $cipher = Crypt::DES->new($key);
        my $decrypted = $cipher->decrypt($encrypted_bytes);
        $decrypted =~ s/\x00+$//;
        
        if ($decrypted =~ /^[\x20-\x7E]+$/ && length($decrypted) > 0) {
            print "SUCCESS with key: " . unpack("H*", $key) . "\n";
            print "Encrypted Hex: $encrypted_hex\n";
            print "Decrypted Password: $decrypted\n";
            exit 0;
        }
    };
}

print "Failed to decrypt with any known VNC key\n";