when HTTP_REQUEST {
  
  # Header name to be used for AD enrichmentn
  set ::HEADER "x-additional-header"
  
  # SALT for randomizing return MD5 hash (Can be any string)
  set ::SALT "hr83AVnwUi9ecD7xD9jntV3gggf932qP"

  # Lookup an internal AAA table to get subscriber related information
  # Must be single string stream.
  set uset_info [table lookup -subtable ip_ro_userinfo [IP::client_addr]]
  set hash ""
  
  if {$uset_info}{
    # Stretching MD5 hash to strengthen hash (may not be necesarry)
    set hash [md5 [$::SALT + $uset_info]]]
  } else {
    set hash "not_available"
  }

  table add -subtable hash_msisdn $hash $uset_info
  
  # Send hash log in LTSV format(http://ltsv.org/)
  log local0.info "$hash :: $uset_info ([IP::client_addr])"
  
  # Insert hash into http_header (canbe cookie as well)
  HTTP::header insert $::HEADER $hash

}
