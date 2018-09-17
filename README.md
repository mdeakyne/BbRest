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
All APIs documented on developer.blackboard.com are not available for all versionsof self and managed hosted clients. The terminology is even a bit hard to decipher, as it doesn't match specifically.  

This wrapper will create functions that only allows calling available functions, depending on the version of Blackboard it connects to.

### Finding APIs
It can be difficult to find the correct API on developers.blackboard.com, and this wrapper allows you to tab complete generated APIs and to get hints about expected inputs.  

### Convenience APIs
This wrapper also has some convenience APIs that make getting information easier.
This is also a work in progress, and probably will be built out separately.

## Installation
Install pipenv
```bash
$ pip3 install pipenv
```

Then, in the cloned bbrest folder
```bash
$ pipenv --three
$ pipenv install
```

This will create a virtual environment with python 3 and the dependencies of this project

## Usage

### Setup
```python
bb = BbRest(key, secret, url)
bb.supported_functions() #generates class methods from bb documentation
```
### Session Management
```python
bb.expiration()
```
'6 minutes ago'
```python
r = bb.getUser(userId='test_user')
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

All available endpoints can be accessed this way.
Params should be entered as `params={'key':'value'}`
Payload should be entered as `payload={'key1':'value1','key2':'value2', etc}`
Working on better exception handling, and a way to view failure history.
Calls will always be authenticated, if the session is expired, it will renew the session.
