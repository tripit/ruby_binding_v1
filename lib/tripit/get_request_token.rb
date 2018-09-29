#!/usr/bin/env ruby
#
# Copyright 2008-2018 Concur Technologies, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

require 'tripit'

if ARGV.length < 3:
    print "Usage: get_request_token.rb api_url consumer_key consumer_secret\n"
    exit 1
end

api_url = ARGV[0]
consumer_key = ARGV[1]
consumer_secret = ARGV[2]
    
oauth_credential = TripIt::OAuthCredential.new(
    consumer_key, consumer_secret)
t = TripIt::API.new(oauth_credential, api_url)

request_token = t.get_request_token

print "request token:  #{request_token.token}\n"
print "request secret: #{request_token.token_secret}\n"
