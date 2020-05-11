
def OnErrorReturnValue(value):
    def decorator(function):
        def wrapper(*args, **kwargs):
            try:
                result = function(*args, **kwargs)
                return result
            except Exception as e:
                #print(e)
                return value
        return wrapper
    return decorator