#!/usr/bin/env ruby
#
# Copyright 2008-2012 Concur Technologies, Inc.
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

if ARGV.length < 5:
    print "Usage: make_post_request.rb api_url consumer_key consumer_secret authorized_token authorized_token_secret"
    exit 1
end

api_url = ARGV[0]
consumer_key = ARGV[1]
consumer_secret = ARGV[2]
authorized_token = ARGV[3]
authorized_token_secret = ARGV[4]

trip_xml = "<Request><Trip>" \
           "<start_date>2009-12-09</start_date>" \
           "<end_date>2009-12-27</end_date>" \
           "<primary_location>New York, NY</primary_location>" \
           "</Trip></Request>"

oauth_credential = TripIt::OAuthCredential.new(
    consumer_key, consumer_secret,
    authorized_token, authorized_token_secret)

t = TripIt::API.new(oauth_credential, api_url)

puts t.create(trip_xml).to_xml.to_s
