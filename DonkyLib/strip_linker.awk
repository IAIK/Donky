BEGIN {
  HEADER=1
}

/* Strip header (footer) */
/===/ {
  HEADER=0;
  next
}

/* Strip SEARCH_DIR */
!HEADER && /SEARCH_DIR/ {
  next
}

/* Insert linker_common.ld before .text segment */
!HEADER && /^\s*\.text\s*:/ {
  print ""
  print "INCLUDE linker_common.ld"
  print ""
  print $0
  next
}

/* Print rest unmodified */
!HEADER && /.*/ {
  print $0
}
