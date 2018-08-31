import maya
import requests
import re

class BbRest:
    session = ''
    expiration_epoch = ''
    version = ''
    functions = {}

    def __init__(self, key, secret, url):
        #these variables are accessible in the class, but not externally.
        self.__key = key
        self.__secret = secret
        self.__url = url

        #Authenticate the session
        session = requests.session()
        payload = {'grant_type':'client_credentials'}

        #Sends a post to get the authentication token
        r = session.post(f"{self.__url}/learn/api/public/v1/oauth2/token",
                     data=payload,
                     auth=(self.__key, self.__secret))

        #Adds the token to the headers for future requests.
        if r.status_code == 200:
            token = r.json()["access_token"]
            session.headers.update({"Authorization":f"Bearer {token}"})
            self.expiration_epoch = maya.now() + r.json()["expires_in"]

        else:
            print('Authorization failed, check your key, secret and url')
            return

        #set the session within the class
        self.session = session

        #get the current version via a REST call
        r = self.session.get(f'{url}/learn/api/public/v1/system/version')
        if r.status_code == 200:
            version = f"{r.json()['learn']['major']}.0.0" #Ignore incremental
        else:
            print(f"Could not retrieve version, error code: {r.status_code}")
            version = '3000.0.0' #Version wasn't supported until 3000.3.0

        #This helps only pull down APIs your version has access to.
        self.version = version

        #get the most up to date swagger_json call
        swagger_json = requests.get('https://developer.blackboard.com/portal/docs/apis/learn-swagger.json').json()
        p = r'\d+.\d+.\d+'
        functions = []
        for path in swagger_json['paths']:
            for call in swagger_json['paths'][path].keys():
                meta = swagger_json['paths'][path][call]
                functions.append(
                    {'summary':meta['summary'].replace(' ',''),
                      'method':call,
                      'path':path,
                      'version':re.findall(p,swagger_json['paths'][path][call]['description'])
                    })

        self.__all_functions = functions

    def is_supported(self, function):
        start = function['version'][0]

        if len(function['version']) == 1:
            return start <= self.version
        else:
            end = function['version'][1]

        return start <= self.version < end

    def supported_functions(self):
        functions = [f for f in self.__all_functions if self.is_supported(f)]
        d_functions = {}
        for function in functions:
            summary = function['summary']
            method = function['method']
            path = function['path']

            if summary in ['GetChildren','GetMemberships']:
                if summary == 'GetChildren' and 'contentId' in path:
                    summary = 'GetContentChildren'
                elif summary == 'GetChildren' and 'courseId' in path:
                    summary = 'GetCourseChildren'
                elif summary == 'GetMemberships' and 'userId' in path:
                    summary = 'GetUserMemberships'
                elif summary == 'GetMemberships' and 'courseId' in path:
                    summary = 'GetCourseMemberships'

            d_functions[summary] = {'method':method,'path':path}
            self.functions = d_functions

    def find_summary(self, search):
        return [f for f in self.functions if search in f]

    def info(self, summary):
        if summary not in self.functions:
            print("That function doesn't exist, try a search with find_summary")
            return

        path = self.functions[summary]['path']
        method = self.functions[summary]['method']
        print(method)
        p = r'{\w+}'

        #the [1:-1] strips off the brackets around each parameter
        params = [param[1:-1] for param in re.findall(p,path)]

        if method in ['get']:
            params.append('params (optional)')
        elif method in ['post','patch','put']:
            params.append('payload')

        param_string = ', '.join(params)
        print(f'Parameters: {param_string}')
        print(f'More information can be found at https://developer.blackboard.com/portal/displayApi')

    def call(self, summary, **kwargs):
        method = self.functions[summary]['method']
        path = self.functions[summary]['path']
        params = ''
        payload = ''

        if 'params' in kwargs:
            params = kwargs['params']
            del kwargs['params']

        if 'payload' in kwargs:
            payload = kwargs['payload']
            del kwargs['payload']

        req = requests.Request(method=method, url=f'{self.__url}{path}')
        req.url = req.url.format(**kwargs)
        req.params = params
        req.json = payload

        prepped = self.session.prepare_request(req)

        if self.is_expired():
            self.refresh_token()

        return self.session.send(prepped)

    def is_expired(self):
        return maya.now() > self.expiration_epoch

    def refresh_token(self):
        payload = {'grant_type':'client_credentials'}

        r = self.session.post(f"{self.__url}/learn/api/public/v1/oauth2/token",
                     data=payload,
                     auth=(self.__key, self.__secret))

        if r.status_code == 200:
            token = r.json()["access_token"]
            self.session.headers.update({"Authorization":f"Bearer {token}"})
            self.expiration_epoch = maya.now() + r.json()["expires_in"]

    def expiration(self):
        return(self.expiration_epoch.slang_time())
