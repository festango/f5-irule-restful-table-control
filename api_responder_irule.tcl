#
# Sample iRule RESTFULL table control rev 0.1 (2013/4/15)
#
#  Written by:  Shun Takahashi
#
#  Description: A sample iRule to provide REST style API for controlling  
#               a session table. The rule will be called when external clients
#				call API enabled virtual server. 
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
timing off
when RULE_INIT {
  set ::API_NAME "api"
  set ::API_VER  "1.0" 
  set ::SUBTBL   "hash_to_userinfo"
  set ::RESOURCE "hashes"
  set ::SALT     "hr83AVnwUi9ecD7xD9jntV3gggf932qP"
}

when HTTP_REQUEST {

  set status  ""
  set content ""
  set host   [IP::client_addr]
  set time   [clock format [clock seconds] -gmt true]
  set req    "[HTTP::method] [HTTP::uri] [HTTP::version]"
  set ref    [HTTP::header "Referer"]
  set ua     [HTTP::header "User-Agent"]

  set path [split [HTTP::path] "/"]

  # Matches /<api_name/<version>/
  if {[lindex $path 1] eq $::API_NAME && [lindex $path 2] eq $::API_VER} {

    append $content "\{\n"
    append $content "  \"name\": \"$::API_NAME\","
    append $content "  \"version\": \"$::API_VER\","
    append $content "  \"query\": \"$req\"\n,"

    if {[lindex $path 3] eq $::RESOURCE} {
      
      # If id is given in path. Ex) /api/ver/res/<id>
      # Validate Key Length as MD5 hash as a key in this iRule
      if {[lindex $path 4] && [string length [lindex $path 4]] == 16} {

        set hash [lindex $path 4]

      	switch [HTTP::method] {
          # GET /api/ver/resource/<key>
          "GET" { 
            set value    [table lookup   -subtalbe $::SUBTBL -notouch]
            set timeout  [table timeout  -subtable $::SUBTBL -notouch]
            set lifetime [table lifetime -subtable $::SUBTBL -notouch] 

            if {$value}{    
              # Only returns value if the value in the table is matched to 
              # calculated MD5 from given hash
              if {[md5 [$::SALT + $value]] equals $hash}{
                set status 200
                append $content "  \"count\": 1,\n"
                append $content "  \"results\":\[\n"
                append $content "    \{\"$key\": \[\"$value\", \"$timeout\", \"$liefime\"\]\}\n"
                append $content "  \],"
              } else {
                set status 
              }
            } else {
              # No value is found correspondent to the given key
              set status 404
            }

          }

          # PUT /api/ver/resource/<key>
          "PUT" {
            if {[table lookup -subtable $::SUBTBL $hash]}{
              table replace -subtable $::SUBTBL
              set status 200
            } else {
              # No value is found correspondent to the given key
              set status 404
            }
          }

          # DELETE /api/ver/resource/<key>
          "DELETE" {
            if {[table lookup -subtable $::SUBTBL $hash]}{
              table delete -subtable $::SUBTBL $hash
              set status 200
            } else {
              # No value is found correspondent to the given key
              set status 404
            }
          }
      	}

      } else {
        # GET /api/ver/res/
        if {HTTP::method eq "GET"} {
          set status 200

          # Limiting number of key to 500 for performance reason
          set keys  [table keys -subtable $::SUBTBL -count 500 -notouch]
          append $content "  \"count\": [llength $keys],\n"
          append $content "  \"results\":\[\n"

          set index 0
          foreach key $keys {

            set value    [table lookup   -subtable $::SUBTBL -notouch]
            set timeout  [table timeout  -subtable $::SUBTBL -notouch]
            set lifetime [table lifetime -subtable $::SUBTBL -notouch]

            append $content "    {\"$key\": [\"$value\", \"$timeout\", \"$liefime\"]}"

            set index [expr {$index + 1}]
            if {$index == [llength $keys]}{
              append $content ",\n"
            } else {
              append $content "\n"              
            }

          }

          append $content "  \],"

        } else {
          # Returns 500 Internal Server Error as none-GET request to resource itself
          # is not supported in this iRule
          set status 500
        }

      }

  } else {
  	# Returns 400 Bad Request if path does not match API name / version
  	set status 400 
  }

  # Generate HTTP response and sent to client
  if {$status == 200}{
    append $content "\}"
	  HTTP::respond $status content $content
  } else {
  	HTTP::respond $status
  }

  # Send API access log in labeled tab-seperated values(LTSV) format
  log local0 "host:$host\ttime:$time\treq:$req\tstatus:$status\treferer:$ref\tua:$ua"

}