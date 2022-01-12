import hashlib

import requests
import logging
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

from login import OneXLogin
from urllib.parse import urlparse, quote
from metadata import CompactMetadata, StandardXMLetadata
from exceptions import NotLoggedIn, MissingVersion, HTTPException, RETSException, MaxrowException

logging.getLogger("urllib3").setLevel(logging.ERROR) #IH

class Session(object):
    """The Session object that makes requests to the RETS Server"""

    allowed_auth = ['basic', 'digest']

    def __init__(self, login_url, username, password=None, version='1.7.2', http_auth='digest',
                 user_agent='Python RETS', user_agent_password=None, cache_metadata=True,
                 follow_redirects=True, use_post_method=True, metadata_format='STANDARD-XML'):
        """
        Session constructor
        :param login_url: The login URL for the RETS feed
        :param version: The RETS version to use. Default is 1.5
        :param username: The username for the RETS feed
        :param password: The password for the RETS feed
        :param user_agent: The useragent for the RETS feed
        :param user_agent_password: The useragent password for the RETS feed
        :param follow_redirects: Follow HTTP redirects or not. The default is to follow them, True.
        :param use_post_method: Use HTTP POST method when making requests instead of GET. The default is True
        :param metadata_format: COMPACT_DECODED or STANDARD_XML. The client will attempt to set this automatically
        based on response codes from the RETS server.
        """
        self.client = requests.Session()
        self.login_url = login_url
        self.username = username
        self.password = password
        self.user_agent = user_agent
        self.user_agent_password = user_agent_password
        self.http_authentication = http_auth
        self.cache_metadata = cache_metadata
        self.capabilities = {}
        self.version = version  # Set by the RETS server response at login. You can override on initialization.

        self.metadata_responses = {}  # Keep metadata in the session instance to avoid consecutive calls to RETS
        self.metadata_format = metadata_format
        self.capabilities = {}

        self.client = requests.Session()
        self.session_id = None
        if self.http_authentication == 'basic':
            self.client.auth = HTTPBasicAuth(self.username, self.password)
            print(f'the authentication methos is {self.http_authentication.title() }.')
        else:
            self.client.auth = HTTPDigestAuth(self.username, self.password)

        self.client.headers = {
            'User-Agent': self.user_agent,
            'RETS-Version': '{0!s}'.format(self.version),
            'Accept-Encoding': 'gzip',
            'Accept': '*/*'
        }
        print(f'client header is ::::::: {self.client.headers}.')

        self.follow_redirects = follow_redirects
        self.use_post_method = use_post_method
        self.add_capability(name=u'Login', uri=self.login_url)

    def __enter__(self):
        """Context Manager: Login when entering context"""
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context Manager: Logout when leaving context"""
        self.logout()

    def add_capability(self, name, uri):
      print('add_capability function is called')
    
      """
      Add a capability of the RETS board
      :param name: The name of the capability
      :param uri: The capability URI given by the RETS board
      :return: None
      """
    
      parse_results = urlparse(uri)
      #print(f' PPPPPPPP: this is url parse:    {parse_results}.')
      if parse_results.hostname is None:
          #print('relative URL given, so build this into an absolute URL')
          login_url = self.capabilities.get('Login')
          if not login_url:
              logger.error("There is no login URL stored, so additional capabilities cannot be added.")
              raise ValueError("Cannot automatically determine absolute path for {0!s} given.".format(uri))
          parts = urlparse(login_url)
          uri = parts.scheme + '://' + parts.hostname + '/' + uri.lstrip('/')
      self.capabilities[name] = uri
      print(f'capabilities: {self.capabilities}')

    def login(self):
      print('login function is called')
      """
      Login to the RETS board and return an instance of Bulletin
      :return: Bulletin instance
      """
      response = self._request('Login')
      print(f'this is the response of login function:     {response}.')
      parser = OneXLogin()
      parser.parse(response)

      self.session_id = response.cookies.get('RETS-Session-ID', '')
      print(f'This is the self.session_id of login function: {self.session_id}.')

      if parser.headers.get('RETS-Version') is not None:
          self.version = str(parser.headers.get('RETS-Version'))
          self.client.headers['RETS-Version'] = self.version

      for k, v in parser.capabilities.items():
          self.add_capability(k, v)

      if self.capabilities.get('Action'):
          self._request('Action')
      return True

    def logout(self):
        print('logout function is called')
        """
        Logs out of the RETS feed destroying the HTTP session.
        :return: True
        """
        self._request(capability='Logout')
        return True

    def get_system_metadata(self):
        print('get_sytem_metadat is called')
        """
        Get the top level metadata
        :return: list
        """
        result = self._make_metadata_request(meta_id='*', metadata_type='METADATA-SYSTEM')
        print(f'result is : {result}')
        # Get dict out of list
        return result.pop()

    def _make_metadata_request(self, meta_id, metadata_type=None):
        print('_make_metadata_request is called')
        """
        Get the Metadata. The Session initializes with 'COMPACT-DECODED' as the format type. If that returns a DTD error
        then we change to the 'STANDARD-XML' format and try again.
        :param meta_id: The name of the resource, class, or lookup to get metadata for
        :param metadata_type: The RETS metadata type
        :return: list
        """
        # If this metadata _request has already happened, returned the saved result.
        key = '{0!s}:{1!s}'.format(metadata_type, meta_id)
        if key in self.metadata_responses and self.cache_metadata:
            response = self.metadata_responses[key]
        else:
            response = self._request(
                capability='GetMetadata',
                options={
                    'query': {
                        'Type': metadata_type,
                        'ID': meta_id,
                        'Format': self.metadata_format
                    }
                }
            )
            self.metadata_responses[key] = response
        print(f'response is :   {response}')

        if self.metadata_format == 'SCOMPACT-DECODED':
            parser = CompactMetadata()
        else:
            parser = StandardXMLetadata()

        try:
            return parser.parse(response=response, metadata_type=metadata_type)
        except RETSException as e:
            # If the server responds with an invalid parameter for COMPACT-DECODED, try STANDARD-XML
            if self.metadata_format != 'STANDARD-XML' and e.reply_code in ['20513', '20514']:
                self.metadata_responses.pop(key, None)
                self.metadata_format = 'STANDARD-XML'
                return self._make_metadata_request(meta_id=meta_id, metadata_type=metadata_type)
            raise RETSException(e.reply_text, e.reply_code)

    def get_resource_metadata(self, resource=None):
        """
        Get resource metadata
        :param resource_id: The name of the resource to get metadata for
        :return: list
        """
        result = self._make_metadata_request(meta_id=0, metadata_type='METADATA-RESOURCE')
        if resource:
            result = next((item for item in result if item['ResourceID'] == resource), None)
        return result

    def _request(self, capability, options=None, stream=False):
        print('_request function is called')
        """
        Make a _request to the RETS server
        :param capability: The name of the capability to use to get the URI
        :param options: Options to put into the _request
        :return: Response
        """
        if options is None:
            options = {}
        options.update({
            'headers': self.client.headers.copy()
        })
       
        url = self.capabilities.get(capability)

        if not url:
            msg = "{0!s} tried but no valid endpoints was found. Did you forget to Login?".format(capability)
            raise NotLoggedIn(msg)
        if self.user_agent_password:
            ua_digest = self._user_agent_digest_hash()
            options['headers']['RETS-UA-Authorization'] = 'Digest {0!s}'.format(ua_digest)
        
        if self.use_post_method and capability != 'Action':  # Action Requests should always be GET
        
            query = options.get('query')
            print(f'query is:  {query}')
            response = self.client.post(url, data=query, headers=options['headers'], stream=stream)
            print(f'Response is: {response}')
        else:
            if 'query' in options:
                url += '?' + '&'.join('{0!s}={1!s}'.format(k, quote(str(v))) for k, v in options['query'].items())
            response = self.client.get(url, headers=options['headers'], stream=stream)
        if response.status_code in [400, 401]:
            if capability == 'Login':
                m = "Could not log into the RETS server with the provided credentials."
            else:
                m = "The RETS server returned a 401 status code. You must be logged in to make this request."
            raise NotLoggedIn(m)
        elif response.status_code == 404 and self.use_post_method:
            raise HTTPException("Got a 404 when making a POST request. Try setting use_post_method=False when "
                                "initializing the Session.")
        return response





#login_url = 'http://sample.data.crea.ca/Login.svc/Login'
login_url = 'https://data.crea.ca/Login.svc/Login'
username = 'CXLHfDVrziCfvwgCuL8nUahC'
password = 'mFqMsCSPdnb5WO1gpEEtDCHH'


s = Session(login_url, username, password)
s.login()
system_data = s.get_system_metadata()
print(system_data)
resources = s.get_resource_metadata(resource='Agent')
print(resources)
s.logout()