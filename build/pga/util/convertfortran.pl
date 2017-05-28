#!/usr/local/bin/perl
#
#  Convert fortran examples to 64-bit compatable codes.
#
#  This script will replace all occurances of "integer ctx" and 
#  "integer comm" with "integer*8 ctx" and "integer*8 comm", respectively.
#  (Uncomment the commented lines below to convert back to 32-bit examples.)
#
#  WARNING:  This is done inplace -- no backup files are created!
#
foreach (@ARGV) {
    print "Converting $_\n";
    $file = $_;
    open(In, "$file"); @Stuff = <In>; close(In);
    foreach (@Stuff) {
        s/integer\s*ctx/integer\*8 ctx/g;
        s/integer\s*comm/integer\*8 comm/g;
#        s/integer\*8\s*ctx/integer ctx/g;
#        s/integer\*8\s*comm/integer comm/g;
    }
    open(Out, ">$file"); print Out @Stuff; close(Out);
}    
