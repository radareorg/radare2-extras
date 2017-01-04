#!/usr/bin/env perl
# generate r2 script out of a snowman decompilation
# author : pancake // nopcode.org // 2016

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
  R2SNOW_SOURCE => "r2snow-source.c"
};

my $source = join("", rf(R2SNOW_SOURCE));
my @addrof = rf("r2snow-addrof.txt");

my $ts = $source;
$ts =~s/reinterpret_cast//g;
$ts =~s/static_cast//g;
wf(R2SNOW_SOURCE . ".txt", $ts);

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

sub lineFor($) {
  my ($offset) = @_;
  my $line = 0;
  foreach my $nl (@nls) {
    if ($nl >= $offset) {
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
  print "CL $file:$line $addr\n";
}
