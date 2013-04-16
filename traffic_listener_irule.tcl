#
#  Sample RESTFULL table control iRule - Traffic Listner rev 0.1 (2013/4/15)
#
#  Written by:  Shun Takahashi
#
#  Description: A sample iRule to provide REST style API for controlling  
#               a session table. The rule will be called when external clients
#       call API enabled virtual server. 
#
#               The rule will return command results in JSON format no matter
#               what client type is accessing. 
#
#               The virtual server like to be different from the one handling
#               actual client / subscriber traffic.
#
#  Information: 
#
#               1) Given Session Table:
#
#                 table set -subtable "hash_to_userinfo" \
#                                     "MD5 hash" "User Information" \
#                                     static::Timeout static::Lifetime
#
#
#               2) REST API structure:
#
#                 URL http://virtual-addr/api/<version>/<resource>/<id>                  
#
#                 GET hashes/          - Returns all values in table
#                 GET hashes/<hash>    - Returns value for hash in session table
#                 PUT hashes/<hash>    - Updates value for hash in session table
#                 DELETE hashes/<hash> - Destroys an entry correspondent to hash
#
#
#               3)Expected Response (JSON)
#
#                 {
#                   "name" : "api",
#                   "version" : 1.0,
#                   "request" : "GET /api/1.0/hashes/07867d0856f063cda129b7351,
#                   "counts"  : 1,
#                   "results" : [
#                     { 07867d0856f063cda129b7351: ["shun", "125", "300"] }
#                   ]
#                 }
#
#
#  Note:        The rule currently does not provide any authentication mechanism
#               to API access. 
#
#
when RULE_INIT {
  # Header name to be used for AD enrichmentn
  set ::HEADER "x-additional-header"
  
  # SALT for randomizing return MD5 hash (Can be any string)
  set ::SALT "hr83AVnwUi9ecD7xD9jntV3gggf932qP"
}

when HTTP_REQUEST {
  
  # Lookup an internal AAA table to get subscriber related information
  # Must be single string stream.
  set uset_info [table lookup -subtable ip_ro_userinfo [IP::client_addr]]
  set hash ""
  
  if { $uset_info }{
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
