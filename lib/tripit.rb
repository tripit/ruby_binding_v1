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

module TripIt
    
require 'rubygems'
require 'openssl'
require 'digest/md5'
require 'base64'
require 'net/http'
require 'net/https'
require 'uri'
require 'cgi'
require 'rexml/document'
require 'json'
require 'date'

# OAuth Core 1.0 Section 5.1 Parameter Encoding
def self.urlencode(str)
    str = str.to_s
    str.gsub(/[^a-zA-Z0-9_\.\-\~]/n) do |s|
        sprintf('%%%02X', s.ord)
    end
end

def self.urlencode_args(args)
    args.collect do |k, v|
        urlencode(k) + '=' + urlencode(v)
    end.join('&')
end

class WebAuthCredential
    def initialize(username, password)
        @username, @password = username, password
    end
    
    def authorize(request, url, args)
        request.basic_auth(@username, @password)
    end
end

class OAuthCredential
    OAUTH_SIGNATURE_METHOD = 'HMAC-SHA1'
    OAUTH_VERSION = '1.0'
    
    def initialize(consumer_key, consumer_secret, token_or_requestor_id='', token_secret='')
        @consumer_key = consumer_key
        @consumer_secret = consumer_secret
        @token = @token_secret = @requestor_id = ''
        if token_or_requestor_id != '' and token_secret != ''
            @token = token_or_requestor_id
            @token_secret = token_secret
        elsif token_or_requestor_id != ''
            @requestor_id = token_or_requestor_id
        end
    end
    
    def authorize(request, url, args)
        request['Authorization'] = \
            generate_authorization_header(request.method, url, args)
    end
    
    def validate_signature(url)
        url = URI(url)
        parsed_params = CGI.parse(url.query)
        params = {}
        parsed_params.each_key do |key|
            params[key.intern] = parsed_params[key][0]
        end
        url.query = nil
        url = url.to_s
        
        signature = params[:oauth_signature]
        puts signature.inspect, generate_signature('GET', url, params).inspect
        
        return signature == generate_signature('GET', url, params)
    end
    
    def get_session_parameters(redirect_url, action)
        parameters = generate_oauth_parameters('GET', action, {'redirect_url' => redirect_url})
        parameters['redirect_url'] = redirect_url;
        parameters['action'] = action
        
        JSON.dump(parameters)
    end
    
    attr_reader :consumer_key, :consumer_secret, :token, :token_secret
    
private
    def generate_authorization_header(http_method, url, args)
        realm = URI(url.scheme + '://' + url.host + ':' + url.port.to_s).to_s
        base_url = URI(url.scheme + '://' + url.host + ':' + url.port.to_s + \
            url.path).to_s
        
        'OAuth realm="' + realm + '",' + \
        generate_oauth_parameters( \
        http_method, base_url, args).collect do |k, v|
            TripIt.urlencode(k) + '="' + TripIt.urlencode(v) + '"'
        end.join(',')
    end
    
    def generate_oauth_parameters(http_method, base_url, args)
        http_method.upcase!
        
        oauth_parameters = {
            :oauth_consumer_key => @consumer_key,
            :oauth_nonce => generate_nonce,
            :oauth_timestamp => Time.now.to_i,
            :oauth_signature_method => OAUTH_SIGNATURE_METHOD,
            :oauth_version => OAUTH_VERSION
        }
        
        if @token != ''
            oauth_parameters[:oauth_token] = @token
        end
        if @requestor_id != ''
            oauth_parameters[:xoauth_requestor_id] = @requestor_id
        end
        
        oauth_parameters_for_base_string = oauth_parameters.dup
        if not args.nil?
            oauth_parameters_for_base_string.merge!(args)
        end
        
        oauth_parameters[:oauth_signature] = generate_signature(http_method, base_url, oauth_parameters_for_base_string)
        
        oauth_parameters
    end
    
    def generate_signature(method, base_url, params)
        base_url = TripIt.urlencode(base_url)
        
        params.delete(:oauth_signature)
        
        # Get a list of the parameters sorted by key and
        # join them in key1=value1&key2=value2 form
        parameters = TripIt.urlencode(params.sort do |a, b|
            a[0].to_s <=> b[0].to_s
        end.collect do |k, v|
            TripIt.urlencode(k) + '=' + TripIt.urlencode(v)
        end.join('&'))
        
        signature_base_string = [method, base_url, parameters].join('&')
        
        key = @consumer_secret + '&' + @token_secret
        
        digest = OpenSSL::Digest::Digest.new('sha1')
        hashed = OpenSSL::HMAC.digest(digest, key, signature_base_string)
        Base64.encode64(hashed).chomp
    end
    
    # OAuth Core 1.0 Section 8 Nonce
    def generate_nonce
        chars = ('0'..'9').to_a
        size = 40
        random = (0...size).collect do
            chars[rand(chars.length)]
        end.join
        Digest::MD5.hexdigest(Time.now.to_f.to_s + random)
    end
end

class TravelObj
    def self.new(element)
        children = Hash.new do |h, k|
            h[k] = []
        end
        elements = {}
        element.elements.each do |e|
            if /^[A-Z]/.match(e.name)
                name = e.name.intern
                klass = if TripIt.const_defined?(name)
                    TripIt.const_get(name)
                else
                    TripIt.const_set(name, Class.new(TravelObj))
                end
                children[klass] << klass.new(e)
            else
                elements[e.name] = \
                if e.name[-4..-1] == 'date' or e.name[-4..-1] == 'time'
                    ::DateTime.parse(e.text)
                else
                    e.text
                end
            end
        end
        if self == TravelObj
            # Root. There will be just one Response object.
            children.values.flatten[0]
        else
            super(children, elements)
        end
    end
    
    def initialize(children, elements)
        @children, @elements = children, elements
    end
    
    def to_xml(container = REXML::Document.new)
        element = container.add_element(self.class.name.split('::')[-1])
        @elements.each_pair do |k, v|
            if not v.nil?
                element.add_element(k).text = if v.kind_of? ::DateTime
                    if k[-4..-1] == 'time'
                        v.strftime('%H:%M:%S')
                    else
                        v.strftime('%Y-%m-%d')
                    end
                else
                    v
                end
            end
        end
        self[].each do |child|
            child.to_xml(element)
        end
        container
    end
    
    def elements
        @elements.keys
    end
    
    def children
        @children.keys
    end
    
    def [](name = nil)
        if name.nil?
            @children.values.flatten
        elsif name.kind_of? Class
            @children[name]
        else
            @elements[name]
        end
    end
    
    def []=(name, value)
        @elements[name] = value
    end
    
    def add_child(obj)
        @children[obj.class] << obj
    end
end

class API
    API_VERSION = 'v1'
    
    def initialize(credential, api_url='https://api.tripit.com', verify_ssl=false)
        @api_url = api_url
        @verify_ssl = verify_ssl
        @credential = credential
    end
    
    attr_reader :credential
    
    def get_request_token
        request_token = parse_query_string(do_request('/oauth/request_token'))
        
        @credential = OAuthCredential.new(@credential.consumer_key, \
            @credential.consumer_secret, \
            request_token['oauth_token'], \
            request_token['oauth_token_secret'])
    end
    
    def get_access_token
        access_token = parse_query_string(do_request('/oauth/access_token'))
        
        @credential = OAuthCredential.new(@credential.consumer_key, \
            @credential.consumer_secret, \
            access_token['oauth_token'], \
            access_token['oauth_token_secret'])
    end
    
    # Public method mappings
    class Verb
        def initialize
            yield self
        end
        
        def entity(*entities, &operation)
            entities.each do |entity|
                class << self
                    self
                end.send :define_method, entity do |*args|
                    operation.call(entity, *args)
                end
            end
        end
    end
    
    # Lists objects
    def list
        @list ||= Verb.new do |verb|
            verb.entity :trip, :object, :points_program do |entity, params|
                do_request('list', entity, params, nil)
            end
        end
    end
    
    # Gets an object by ID, or in the case of trips, with an optional filter
    def get
        @get ||= Verb.new do |verb|
            verb.entity :air, :lodging, :car, :parking, :rail, :transport, \
                :cruise, :restaurant, :activity, :note, :map, :directions, \
                :points_program \
            do |entity, id|
                do_request('get', entity, {:id=>id}, nil)
            end
            
            verb.entity :profile do |*args|
                entity = args[0]
                do_request('get', entity, nil, nil)
            end
            
            verb.entity :trip do |*args|
                entity, id, filter = args
                if filter.nil?
                    filter = {}
                end
                filter[:id] = id
                do_request('get', entity, filter, nil)
            end
        end
    end
    
    # Deletes an object by ID
    def delete
        @delete ||= Verb.new do |verb|
            verb.entity :trip, :air, :lodging, :car, :parking, :profile, :rail, \
                :transport, :cruise, :restaurant, :activity, :note, :map, \
                :directions \
            do |entity, id|
                do_request('delete', entity, {:id=>id}, nil)
            end
        end
    end
    
    # Takes either a TravelObj (as long as it is a valid top level Request
    # type), or a full XML Request
    def create(obj)
        do_request('create', nil, nil, {'xml' => obj_to_xml(obj)})
    end
    
    # Takes and ID and  either a TravelObj (as long as it is a valid top level
    # Request type), or a full XML Request.
    # Equivalent to a delete and a create, but they happen atomically.
    def replace
        @replace ||= Verb.new do |verb|
            verb.entity :trip, :air, :lodging, :car, :parking, :profile, :rail, \
                :transport, :cruise, :restaurant, :activity, :note, :map, \
                :directions \
            do |entity, id, obj|
                do_request('replace', entity, nil, {'id' => id, 'xml'=> obj_to_xml(obj)})
            end
        end
    end
    
    def crs_load_reservations(obj, company_key=nil)
        args = {'xml' => obj_to_xml(obj)}
        if not company_key.nil?
            args['company_key'] = company_key
        end
        do_request('crsLoadReservations', nil, nil, args)
    end
    
    def crs_delete_reservations(record_locator)
        do_request('crsDeleteReservations', nil, {'record_locator' => record_locator}, nil)
    end
    
private

    def obj_to_xml(obj)
        if obj.kind_of? TravelObj
            document = REXML::Document.new
            element = document.add_element('Request')
            obj.to_xml(element)
            document.to_s
        else
            obj.to_s
        end
    end
    
    def parse_query_string(string)
        params = {}
        string.split('&').each do |param|
            k, v = param.split('=', 2)
            params[k] = v
        end
        params
    end
    
    def parse_xml(xml)
        TravelObj.new(REXML::Document.new(xml))
    end
    
    # Makes a request POST/GET to the API and returns the response
    # from the server.
    # Throws an exception on error (non-200 response from the server).
    def do_request(verb, entity=nil, url_args=nil, post_args=nil)
        should_parse_xml = true
        url = URI(@api_url)
        if ['/oauth/request_token', '/oauth/access_token'].include?(verb)
            should_parse_xml = false
            url.path = verb
        else
            if not entity.nil?
                url.path = ['', API_VERSION, verb, entity].join('/')
            else
                url.path = ['', API_VERSION, verb].join('/')
            end
        end
        
        args = nil
        if not url_args.nil?
            args = url_args
            url.query = TripIt.urlencode_args(url_args)
        end
        
        request = nil
        if not post_args.nil?
            args = post_args
            request = Net::HTTP::Post.new(url.path)
            request.set_form_data(post_args)
        else
            request = Net::HTTP::Get.new(url.request_uri)
        end
        
        @credential.authorize(request, url, args)
        
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        if @verify_ssl
            http.verify_mode = OpenSSL::SSL::VERIFY_PEER
        end
        response = http.start do
            http.request(request)
        end
        
        if response.code == '200'
            if should_parse_xml
                parse_xml(response.body)
            else
                response.body
            end
        else
            response.error!
        end
    end
end

end
