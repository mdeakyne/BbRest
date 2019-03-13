# BbRest
Blackboard REST APIs... for humans? (TM)

## Purpose
This Python library was created to make the Blackboard REST API more accessible.
Specifically, it helps solve a few problems:

### Token Management
Blackboard tokens expire in one hour, and cannot be expired manually.  
It's possible that two uses of one app would be called within an hour of
starting the other - in this case, the session expires in less than an hour.
A call with an expired token returns a 401 error.

This wrapper has a self healing session that renews the token when needed.

### API availability by version
All APIs documented on developer.blackboard.com are not available for all versions of self and managed hosted clients. The terminology is even a bit hard to decipher, as it doesn't match the QX 20XX format most admins are used to.  

This wrapper will create functions that only allows calling available functions, depending on the version of Blackboard it connects to. This has recently been improved by the distinct versions for .json.

### Finding APIs
It can be difficult to find the correct API on developers.blackboard.com, and this wrapper allows you to tab complete generated APIs and to get hints about expected inputs.  

### Convenience APIs
This wrapper also has some convenience APIs that make getting information easier.
This is also a work in progress, and probably will be built out separately.

## Installation
Install poetry and bbrest
```bash
$ poetry init
$ poetry add bbrest

This will create a virtual environment with python 3 and the dependencies of this project
```
#Install and run JupyterLab
```bash
$ poetry add --dev jupyterlab
$ poetry run jupyter lab
```

## Usage

### Setup
The key and secret are from your registration on developer.blackboard.com.
The url is the base url for your campus ie: https://blackboard.school.edu
```python
from bbrest import BbRest
bb = BbRest(key, secret, url)
```
### Session Management
```python
bb.expiration()
```
'6 minutes ago'
```python
r = bb.GetUser(userId='test_user')
r.status_code
```
200

The call method checks if the session is expired, and renews the token if so.  Other methods around token management:

```python
r = bb.is_expired() #returns boolean
r = bb.refresh_token() #manually refreshes the token
```

Note, refresh_token will receive the same token from Blackboard if the token is not yet expired, even if there's only seconds left.

### REST call discovery / usage with Tab completion
Find all endpoints available in the current version that have 'GetUs' in the name.
```python
r = bb.GetUs<Tab>
```
  * bb.GetUser
  * bb.GetUserGrades
  * bb.GetUserMemberships
  * bb.GetUsers

Find the parameters of 'GetColumnGrade'
```python
r = bb.GetColumnGrade(<Tab>)
```
  * columnId=
  * courseId=
  * userId=

All available endpoints can be accessed this way.
Params should be entered as `params={'key':'value'}`
Payload should be entered as `payload={'key1':'value1','key2':'value2', etc}`

### Calling API endpoints
```python
#Some convenience tricks for common calls
r = bb.GetCourse(courseId='2832102')

#same as above
r = bb.call('GetCourse',courseId='courseId:2832102')
r.json()

r = bb.UpdateCourseMembership(courseId='2832102',
                              userId='test_user',
                              payload={'availability':{'available':'No'}})

#same as above
r = bb.call('UpdateCourseMembership',courseId='courseId:2832102',userId='userName:test_user',payload={'availability':{'available':'No'}})
r.json()
```
### Asynchronous calls!
One of the big advantages of javascript over python was the idea of promises and asynchronous information gathering. Python now has await and async capabilities, but using it can be tricky. 

I've tried to make using it with BbRest to be as easy as possible.

```python
user_info = await bb.GetUser('test_user', asynch=True)
```

NOTE: Based on how this is setup - you get back a dict object on success or failure.  The failure has a status, but the success only has the info.  This is slightly different than how it works synchronously, and has the potential to cause logic errors in the code.

Here's an example of multiple calls:
```python
#Assume users is a list of userNames
tasks = []
for user in users:
  tasks.append(bb.GetUser(user), asynch=True)
resps = await asynchio.gather(*tasks)
```

Since these calls are asynchronous, it's MUCH faster than synchronously going through all users. 

### Working on
Matching up the responses of Async and Sync functions
Better exception handling, and a way to view failure history.
Calls will always be authenticated, if the session is expired, it will renew the session.
