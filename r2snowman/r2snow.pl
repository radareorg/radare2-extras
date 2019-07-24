#!/usr/bin/env perl
# generate r2 script out of a snowman decompilation
# author : pancake // nopcode.org // 2016

use MIME::Base64;

sub rf {
  my ($file) = shift;
  open FH, $file or die "cannot open $file";
  my @lines = <FH>;
  close FH;
  return @lines;
}

sub wf {
  my ($file, $data) = @_;
  open FH, ">$file" or die "cannot open $file";
  print FH $data;
  close FH;
}

use constant {
  R2SNOW_SOURCE => "r2snow-source.c",
  R2SNOW_ADDROF => "r2snow-addrof.txt"
};

if ($arg == '-a') {
  print($ts);
}

if ($arg == '-f') {
my $off = $ENV{"R2_OFFSET"};
print(functionAt(lineFor(scalar $off)));
  exit();

}
if ($arg == '-r') {
# do nothing, defaults
}

my $source = join("", rf(R2SNOW_SOURCE));
my @addrof = rf(R2SNOW_ADDROF);

my $ts = $source;
$ts =~s/reinterpret_cast//g;
$ts =~s/static_cast//g;
wf(R2SNOW_SOURCE . ".txt", $ts);

local @nts = split /\n/g,$ts;

local @nls = ();
sub initNewlines() {
  my $offset = 0;
  my $result = index($source, "\n", $offset);
  while ($result != -1) {
    push (@nls, $offset);
    $offset = $result + 1;
    $result = index($source, "\n", $offset);
  }
}

sub functionAt($) {
  my ($ln) = @_;
  my $line = 1;
  my $findeof = 0;
  my $text = "";
  foreach my $nt (@nts) {
    if ($nt=~/^ /) {
      $text .= $nt . "\n";
    } else {
      if ($findeof) {
        return $text . $nt . "\n";
      } else {
        $text = $nt . "\n";
      }
    }
    if ($line >= $ln) {
      $findeof = 1;
    }
    $line++;
  }
  return "";
}

sub lineFor($) {
  my ($offset) = @_;
  my $line = 0;
  foreach my $a (@addrof) {
    my ($addr, $off) = split(" ", $a);
    if (hex($addr) >= $offset) {
      return $line;
    }
    $line++;
  }
  return 0;
}

initNewlines();


foreach my $a (@addrof) {
  my ($addr, $offset) = split(" ", $a);
  my $file = R2SNOW_SOURCE . ".txt";
  my $line = lineFor($offset);
  my $text = @nts[$line - 1];
  my $txt64 = encode_base64($text);
  $txt64 =~ s/\n//g;
  print "CCu base64:$txt64 @ $addr\n";
  #print "CL $file:$line $addr\n";
}

unlink(R2SNOW_SOURCE);
unlink(R2SNOW_SOURCE.".txt");
