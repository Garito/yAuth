# yAuth Change Log
## 0.1.1
### Drop sanic-jwt dependency
In the process of introspecting ySanic and yModels, the realization that sanic-jwt is a huge flexible solution for a lot of use cases but too much for the need of JWT token authentication was pretty evident

The solution has been implemented with a sanic-jwt dependency pyJWT and yModels as should be obvious

Could be an oversimplified solution but is lean and doesn't add more complexity

### Allowed decorator
allowed decorator allow to define the security requirements of an endpoint

It has two forms:
```allowed(["admin"])``` where you pass a list of roles that are compared to the actor's running the endpoint (obviously the User model needs to define roles) and ```allowed(lambda context, actor: context.owner == actor.slug)``` where you pass a function that recieves a context (the model object where the endpoint is runned) and the actor that runs the endpoint. It passes if the lambda returns True

### Permission decorator
Allow to define the permissions for the member
It can be empty so the permission will be ```<Model>/<member>```
