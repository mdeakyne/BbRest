import maya
import requests
from requests.models import Response
import json
import types
import asyncio
import aiohttp
from aiohttp import web
import urllib
import urllib.parse as urlparse
import re
from selenium import webdriver

with open('ent_map.json','r') as fp:
    ent_map = json.load(fp)

class BbRest:
    session = ''
    expiration_epoch = ''
    version = ''
    functions = {}

    def __init__(self, key, secret, url, headers=None, user='', pwd='', scope='read'):
        #these variables are accessible in the class, but not externally.
        self.__key = key
        self.__secret = secret
        self.__url = url
        self.__headers = headers

        #Authenticate the session
        session = requests.Session()
        payload = {'grant_type':'client_credentials'}

        if self.__headers:
            session.headers.update(self.__headers)

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
            major = r.json()['learn']['major']
            minor = r.json()['learn']['minor']
            version = f"{major}.{minor}.0" #Ignore incremental patches
        else:
            print(f"Could not retrieve version, error code: {r.status_code}")
            version = '3000.0.0' #Version wasn't supported until 3000.3.0

        #This helps only pull down APIs your version has access to.
        self.version = version

        #use the functions that exist in functions.p,
        #or retrieve from the swagger_json definitions
    
        swagger_json = requests.get(f'https://developer.blackboard.com/portal/docs/apis/learn-swagger.json').json()
        p = r'\d+.\d+.\d+'
        q = r'[A-Za-z]+\.[A-Za-z]+\.[A-Za-z]+\.?[A-Za-z]*\.?[A-Za-z]*'
        functions = []
        for path in swagger_json['paths']:
            for call in swagger_json['paths'][path].keys():
                meta = swagger_json['paths'][path][call]
                perms = re.findall(q, meta['description'])
                
                description = meta['description']
                for perm in perms:
                    if perm.lower() in ent_map:
                        description = description.replace(perm, ent_map[perm.lower()])
                functions.append(
                    {'summary':meta['summary'].replace(' ',''),
                        'description':description,
                        'parameters':meta['parameters'],
                        'method':call,
                        'path':path,
                        'version':re.findall(p,meta['description']),
                        'permissions': perms
                    })
       

        #store all functions in a class visible list
        self.__all_functions = functions
        self.supported_functions()
        self.method_generator()

        if user:
            from splinter import Browser
            r = self.AuthorizationCode(params={'redirect_uri':'https://localhost/',
                                        'response_type':'code', 
                                        'client_id':self.__key, 
                                        'scope':scope,
                                        'state':'DC1067EE-63B9-40FE-A0AD-B9AC069BF4B0'})
            options = webdriver.ChromeOptions()
            options.add_argument('headless')
            driver = webdriver.Chrome(chrome_options=options)

            driver.get(r.url)
            
            request_cookies_browser = driver.get_cookies()

            s = requests.Session()
            c = [s.cookies.set(c['name'], c['value']) for c in request_cookies_browser]

            res = s.get(r.url)
            nonceHTML = res.content.decode()
            pattern = 'nonce.*value.*.([a-f0-9\-]{36})'

            nonceList = re.findall(pattern, nonceHTML)
            nonceValue = nonceList[0]

            login_data = {'action':'login', 'login':'Login', 
                  'user_id':user,
                  'password':pwd, 
                  'blackboard.platform.security.NonceUtil.nonce':nonceValue,
                  'new_loc':'/webapps/api-gateway/oauth2/authorizationcode?response_type=code&client_id=d279753a-8319-4910-8b27-0ed5de84bcaf&redirect_uri=https%3A%2F%2Flocalhost%2F&scope=read&state=DC1067EE-63B9-40FE-A0AD-B9AC069BF4B0'}
            
            resp = s.post(r.url, data=login_data)
            
            dict_resp_cookies = resp.cookies.get_dict()
            response_cookies_browser = [{'name':name, 'value':value} for name, value in dict_resp_cookies.items()]
            c = [driver.add_cookie(c) for c in response_cookies_browser]

            driver.get(resp.url)
            
            url = driver.current_url
            if 'code=' in url:
                #print(url)
                params = urlparse.parse_qs(urlparse.urlparse(url).query)
                code = params['code'][0]
                driver.quit()

            else:
                print('expected code in url')
                print(url)
                return

            r = session.post(f"{self.__url}/learn/api/public/v1/oauth2/token",
                     params = {'code':code, 'redirect_uri':'https://localhost/'},
                     data={'grant_type':'authorization_code'},
                     auth=(self.__key, self.__secret))

            #Adds the token to the headers for future requests.
            if r.status_code == 200:
                token = r.json()["access_token"]
                session.headers.update({"Authorization":f"Bearer {token}"})
                self.expiration_epoch = maya.now() + r.json()["expires_in"]
                self.user = r.json()['user_id']
                print(r.json())
            else:
                print('Authorization failed, check your key, secret, url and login info')
                return

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
        functions = [f for f in self.__all_functions if self.is_supported(f)]
        #functions = [f for f in self.__all_functions]
        
        #generate a dictionary of supported methods
        d_functions = {}
        for function in functions:
            summary = function['summary']
            description = function['description']
            parameters = function['parameters']
            method = function['method']
            path = function['path']
            permissions = function['permissions']
            
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

            if method == 'post':
                parameters = clean_params(parameters)

            d_functions[summary] = {'method':method,
                                    'path':path,
                                    'description':description,
                                    'parameters':parameters,
                                    'permissions':permissions}
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
            permissions = functions[function]['permissions']
            
            p = r'{\w+}'
            def_params = ['self']+[param[1:-1]+'= None' for param in re.findall(p,path)]
            params = [param[1:-1]+'= '+param[1:-1] for param in re.findall(p,path)]
            
            #put, post, patch methods have payload as an argument
            #get has params as an argument 
            if functions[function]['method'][0] == 'p':
                def_params.append('payload= {}')
                params.append('payload= payload')
            
            if functions[function]['method'] == 'get':
                def_params.append('params= {}')
                params.append('params= params')

                if function[-1] == 's' or function.endswith("Children"):
                    def_params.append('limit= 100')
                    params.append('limit= limit')

            def_params.append('sync= True')
            params.append('sync= sync')

            def_param_string = ', '.join(def_params)
            param_string = ', '.join(params)

            exec(f"""def {function}({def_param_string}): return self.call('{function}', **clean_kwargs({param_string}))""")
            exec(f"""{function}.__doc__ = '''{description}\nParameters:\n{parameters}\nPermissions:\{permissions} '''""")
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
        params = kwargs.get('params',  {})
        payload = kwargs.get('payload', {})
        limit = kwargs.get('limit', 100)

        if limit == 100:
            async with aiohttp.ClientSession(headers=self.session.headers) as session:
                async with session.request(method, url=url, json=payload, params=params) as resp:
                    ret_resp = Response()
                    ret_resp.status_code = resp.status
                    ret_resp.error_type = resp.reason
                    ret_resp._content = await resp.read()
                    return ret_resp

        tasks = []
        for i in range(0,limit,100):
            new_params = params.copy()
            new_kwargs = kwargs.copy()

            new_params['limit'] = 100
            new_params['offset'] = i
            del new_kwargs['params']
            new_kwargs['limit'] = 100
            tasks.append(self.acall(summary, params=new_params, **new_kwargs))

        resps = await asyncio.gather(*tasks)
        resps_json = [resp.json() for resp in resps]
        results = []
        for resp in resps_json:
            if 'results' in resp:
                #print(f"There are {len(resp['results'])} results in this response")
                results.extend(resp['results'])
                #print(len(results))
        
        
        if 'paging' in resps_json[-1]:
            resp['paging'] = resps_json[-1]['paging']

        if len(results) > limit:
            resp = {'results':results[:limit]}
            params['offset'] = limit
            resp['paging'] = {'nextPage': f'{url}?{urllib.parse.urlencode(params)}'}
        else:
            resp['results'] = results

        ret_resp = Response()
        ret_resp.status_code = 200
        ret_resp._content = json.dumps(resp).encode('utf-8')
        ret_resp.url = url
        return ret_resp


    def call(self, summary, **kwargs):
        r'''   Constructs and sends a :class:`Request <Request>`.
        :param summary: method for the new `Request` .
        :param params: (optional) Dictionary, list of tuples or bytes to send
            in the body of the :class:`Request`.
        :param payload: (optional) A JSON serializable Python object to send in the body of the :class:`Request`.
        :return: :class:`Response <Response>` object
        :rtype: requests.Response
        '''
        if kwargs.get('sync','') != True:
            return self.acall(summary, **kwargs)

        
        method = self.functions[summary]['method']
        path = self.__url + self.functions[summary]['path']
        url = path.format(**kwargs)
        params = kwargs.get('params', {})
        payload = kwargs.get('payload', {})
        limit = kwargs.get('limit', 100)

        if self.is_expired():
            self.refresh_token()

        
        req = requests.Request(method=method, 
                               url=url,
                              params = params,
                              json = payload)

        prepped = self.session.prepare_request(req)
        
        
        resp = self.session.send(prepped)
        ret_resp = resp
        
        try:
            cur_resp = resp.json()
        except json.JSONDecodeError:
            return resp

        if 'results' in cur_resp:
            all_resp = {'results':cur_resp['results']}
            while 'paging' in cur_resp and len(all_resp['results']) < limit:
                next_page = self.__url + cur_resp['paging']['nextPage']
                req = requests.Request(method=method, 
                               url=next_page)
                prepped = self.session.prepare_request(req)
                cur_resp = self.session.send(prepped).json()
                if 'results' in cur_resp:
                    all_resp['results'].extend(cur_resp['results'])
                if 'paging' in cur_resp:
                    all_resp['paging'] = cur_resp['paging']
                elif 'paging' in all_resp:
                    del all_resp['paging']
           
            
            if len(all_resp['results']) > limit:
                all_resp['results'] = all_resp['results'][:limit]
                if 'paging' in cur_resp:
                    vals = cur_resp['paging']['nextPage'].split('=')
                    vals[-1] = str(limit)
                    all_resp['paging'] = {'nextPage':'='.join(vals)}

                else:
                    new_params = params.copy()
                    new_params['offset'] = limit
                    all_resp['paging'] = {}
                    all_resp['paging']['nextPage'] = (self.__url + 
                                                      self.functions[summary]['path'] +
                                                      '?' +
                                                      urllib.parse.urlencode(new_params))
        else:
            return resp

        
        ret_resp = Response()
        ret_resp.status_code = 200
        ret_resp.url = url
        ret_resp._content = json.dumps(all_resp).encode('utf-8')
        
        return ret_resp
        
    
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
                kwargs['userId'] = f'userName:{userId}'

            else:
                kwargs['userId'] = userId

        if courseId:
            if courseId[0] != '_' and ':' not in courseId:
                kwargs['courseId'] = f'courseId:{courseId}'
            else:
                kwargs['courseId'] = courseId

        if columnId:
            if columnId[0] != '_' and columnId != 'finalGrade':
                kwargs['columnId'] = f'externalId:{columnId}'
            else:
                kwargs['columnId'] = columnId

        if groupId:
            if groupId[0] != '_':
                kwargs['groupId'] = f'externalId:{groupId}'
            else:
                kwargs['groupId'] = groupId

        return kwargs

def clean_params(parameters):
    ret_string = ''
    params = [param['schema'] for param in parameters if 'schema' in param]
    if not params:
        return parameters

    required = params[0].get('required', [])
    props = params[0].get('properties',[])
    for key in props:
        prop_key = f'{key} -optional '
        if key in required:
            prop_key=f'{key} **required**'
        prop_type = props[key].get("type","")
        prop_desc = props[key].get("description","")
        prop_enum = props[key].get("enum", "")
        prop_items = props[key].get("items")
        
        enum_str = ''
        items_str = ''
        
        if prop_type:
            type_str = f'\n\ttype: {prop_type}'
        if prop_desc:
            desc_str = f'\n\tdescription: {prop_desc}'
        if prop_enum:
            enum_str = f'\n\tenum: {prop_enum}'
        if prop_items:
            items_str = f'\n\titems: {prop_items}'
        
        
        ret_string += f'-----------------\n{prop_key}{type_str}{desc_str}{enum_str}{items_str}\n-----------------'
    
    return ret_string    