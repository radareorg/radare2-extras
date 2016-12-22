#!/usr/bin/env perl
# generate r2 script out of a snowman decompilation
# author : pancake // nopcode.org // 2016
use File::Slurp;

use constant {
  R2SNOW_SOURCE => "r2snow-source.c"
};

my $source = read_file(R2SNOW_SOURCE);
my @addrof = read_file("r2snow-addrof.txt");

$source =~s/reinterpret_cast//g;
$source =~s/static_cast//g;

write_file R2SNOW_SOURCE, $source;

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
  my $line = 1;
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
  my $file = R2SNOW_SOURCE;
  my $line = lineFor($offset);
  print "CL $file:$line $addr\n";
}
