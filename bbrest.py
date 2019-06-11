import maya
import requests
import re
import types
import asyncio
import aiohttp

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
        session = requests.Session()
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

        #use the functions that exist in functions.p,
        #or retrieve from the swagger_json definitions
    
        swagger_json = requests.get(f'https://developer.blackboard.com/portal/docs/apis/learn-swagger-{version}.json').json()
        p = r'\d+.\d+.\d+'
        functions = []
        for path in swagger_json['paths']:
            for call in swagger_json['paths'][path].keys():
                meta = swagger_json['paths'][path][call]
                functions.append(
                    {'summary':meta['summary'].replace(' ',''),
                        'description':meta['description'],
                        'parameters':meta['parameters'],
                        'method':call,
                        'path':path,
                        #'version':re.findall(p,meta['description'])
                    })
       

        #store all functions in a class visible list
        self.__all_functions = functions
        self.supported_functions()
        self.method_generator()

    def is_supported(self, function):
        if not function['version']:
            return False
        
        start = function['version'][0]
        
        if len(function['version']) == 1:
            return start <= self.version
        else:
            end = function['version'][1]

        return start <= self.version < end

    def supported_functions(self):
        """
        This method generates all API methods for the BB class, using some python magic.
        There are three primary benefits against generating a file:
            1. Obfuscation of paths - there's no risk of publishing url information.
            2. Auto Updates - choses correct version of the path based on internal version.
            3. Self contained class - no need to pass the BbSession elsewhere.
        """

        #filter out unsupported rest calls, based on current version
        #functions = [f for f in self.__all_functions if self.is_supported(f)]
        functions = [f for f in self.__all_functions]
        
        #generate a dictionary of supported methods
        d_functions = {}
        for function in functions:
            summary = function['summary']
            description = function['description']
            parameters = function['parameters']
            method = function['method']
            path = function['path']
            
            #Work around for 4 methods with similar names.
            if summary in ['GetChildren','GetMemberships']:
                if summary == 'GetChildren' and 'contentId' in path:
                    summary = 'GetContentChildren'
                elif summary == 'GetChildren' and 'courseId' in path:
                    summary = 'GetCourseChildren'
                elif summary == 'GetMemberships' and 'userId' in path:
                    summary = 'GetUserMemberships'
                elif summary == 'GetMemberships' and 'courseId' in path:
                    summary = 'GetCourseMemberships'

            d_functions[summary] = {'method':method,
                                    'path':path,
                                    'description':description,
                                    'parameters':parameters}
        self.functions = d_functions
        
    def method_generator(self):
        #Go through each supported method, and figure out parameters,
        #Then create a function on the fly, and save this function as a class method.
        #This is complex, and probably not pythonic, but the results are hard to argue with.
        functions = self.functions
        for function in functions:
            path = functions[function]['path']
            description = functions[function]['description']
            parameters = functions[function]['parameters']
            
            p = r'{\w+}'
            def_params = ['self']+[param[1:-1]+'= None' for param in re.findall(p,path)]+['**kwargs']
            params = [param[1:-1]+'= '+param[1:-1] for param in re.findall(p,path)]+['**kwargs']

            def_param_string = ', '.join(def_params)
            param_string = ', '.join(params)

            exec(f"""def {function}({def_param_string}): return self.call('{function}', **clean_kwargs({param_string}))""")
            exec(f"""{function}.__doc__ = '''{description}\nParameters:\n{parameters}\n '''""")
            exec(f"""self.{function} = types.MethodType({function},self)""")  
            
            
            #One way to get async methods is to generate them all
            #I opted to use a keyword argument instead, asynch, 
            #to reduce the number of methods.
            
            #exec(f"""async def {function}Async({def_param_string}): return await self.acall('{function}', **clean_kwargs({param_string}))""")
            #exec(f"""{function}Async.__doc__ = '''{description}\nParameters:\n{parameters}\n '''""")
            #exec(f"""self.{function}Async = types.MethodType({function}Async,self)""")  
            
        
    async def acall(self, summary, **kwargs):
        if self.is_expired():
            self.refresh_token()
        method = self.functions[summary]['method']
        path = self.__url + self.functions[summary]['path']
        url = path.format(**kwargs)
        params = kwargs.get('params',  '')
        payload = kwargs.get('payload', '')

        async with aiohttp.ClientSession(headers=self.session.headers) as session:
            async with session.request(method, url=url, json=payload, params=params) as resp:
                return await resp.json()

    
    def call(self, summary, **kwargs):
        r'''   Constructs and sends a :class:`Request <Request>`.
        :param summary: method for the new `Request` .
        :param params: (optional) Dictionary, list of tuples or bytes to send
            in the body of the :class:`Request`.
        :param payload: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
        :return: :class:`Response <Response>` object
        :rtype: requests.Response
        '''
        if kwargs.get('asynch','') == True:
            return self.acall(summary, **kwargs)
        
        method = self.functions[summary]['method']
        path = self.__url + self.functions[summary]['path']
        url = path.format(**kwargs)
        params = kwargs.get('params',  '')
        payload = kwargs.get('payload', '')

        if self.is_expired():
            self.refresh_token()

        
        req = requests.Request(method=method, 
                               url=url,
                              params = params,
                              json = payload)

        prepped = self.session.prepare_request(req)

        return self.session.send(prepped)

    def get_all(self, summary, **kwargs):
        r'''   Pages through responses and gathers all responses from :class:`Request <Request>`.
        :param summary: method for the Get `Request` .
        :param params: (optional) Dictionary, list of tuples or bytes to send
            in the body of the :class:`Request`.
        :param max_limit: (optional) total number of JSON objects to return.
        :param limit: (optional) number of JSON objects to fetch each call.
        :return: list of either max_limit, or total json objects.
        :rtype: list of (json)
        '''
        if 'Get' not in summary:
            print('This only works for Get Calls')
            return []

        results = []
        offset = 0

        max_limit = kwargs.get('max_limit',1000)
        kwargs['params'] = kwargs.get('params', {})

        limit = kwargs.get('limit',100)
        kwargs['params']['limit'] = limit

        while offset < max_limit:
            kwargs['params']['offset'] = offset
            r = self.call(summary, **kwargs)
            r_json = r.json()
            if 'results' in r_json:
                results.extend(r.json()['results'])

            if 'paging' not in r_json:
                break

            else:
                offset += limit

        return results
    
    async def get_all_async(self, summary, **kwargs):
        r'''   Pages through responses and gathers all responses from :class:`Request <Request>`.
        :param summary: method for the Get `Request` .
        :param params: (optional) Dictionary, list of tuples or bytes to send
            in the body of the :class:`Request`.
        :param max_limit: (optional) total number of JSON objects to return.
        :param limit: (optional) number of JSON objects to fetch each call.
        :return: list of either max_limit, or total json objects.
        :rtype: list of (json)
        '''
        if 'Get' not in summary:
            print('This only works for Get Calls')
            return {'status':'401', 'message':'This only works for GET calls'}

        results = []
        offset = 0

        max_limit = kwargs.get('max_limit',1000)
        kwargs['params'] = kwargs.get('params', {})

        limit = kwargs.get('limit',100)
        kwargs['params']['limit'] = limit
        
        tasks = []
        #print(limit)
        for i in range(0,max_limit,limit): 
            tasks.append(self.acall('GetCourseMemberships',
                                  courseId='TST-101', 
                                  params={'limit':limit, 
                                  'offset':i}))

        resps = await asyncio.gather(*tasks)
        
        results = []
        #print(len(resps))
        for resp in resps:
            if 'results' in resp:
                #print(len(resp['results']))
                results.extend(resp['results'])
        
        return results

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

    def calls_remaining(self):
        r = self.GetUser(userId='dne')
        
        if 'X-Rate-Limit-Remaining' not in r.headers:
            print('Rate limits not in the headers for your version')
            return 
        
        calls_limit = int(r.headers['X-Rate-Limit-Limit'])
        calls_remaining = int(r.headers['X-Rate-Limit-Remaining'])
        reset_seconds = int(r.headers['X-Rate-Limit-Reset'])
        
        calls_perc = (100 * calls_remaining / calls_limit)
        reset_time = maya.now() + reset_seconds
        used_calls = calls_limit - calls_remaining
        #weird fomatting issue with f-strings, didn't want to display tabs.
        call_str = f"""You've used {used_calls} REST calls so far.\nYou have {calls_perc:.2f}% left until {reset_time.slang_time()}\nAfter that, they should reset"""
        print(call_str)


def clean_kwargs(courseId=None, userId=None, columnId=None, groupId=None, **kwargs):
        if userId:
            if userId[0] != '_' and ':' not in userId:
                kwargs['userId'] = 'userName:{username}'.format(username=userId)

            else:
                kwargs['userId'] = userId

        if courseId:
            if courseId[0] != '_' and ':' not in courseId:
                kwargs['courseId'] = 'courseId:{courseId}'.format(courseId=courseId)
            else:
                kwargs['courseId'] = courseId

        if columnId:
            if columnId[0] != '_' and columnId != 'finalGrade':
                kwargs['columnId'] = 'externalId:{columnId}'.format(columnId=columnId)
            else:
                kwargs['columnId'] = columnId

        if groupId:
            if groupId[0] != '_':
                kwargs['groupId'] = 'externalId:{groupId}'.format(groupId=groupId)
            else:
                kwargs['groupId'] = groupId

        return kwargs