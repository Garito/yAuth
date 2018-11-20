# yAuth Change Log
## 0.1.1
allowed decorator allow to define the security requirements of an endpoint

It has two forms:
```allowed(["admin"])``` where you pass a list of roles that are compared to the actor's running the endpoint (obviously the User model needs to define roles) and ```allowed(lambda context, actor: context.owner == actor.slug)``` where you pass a function that recieves a context (the model object where the endpoint is runned) and the actor that runs the endpoint. It passes if the lambda returns True