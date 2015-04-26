
# from: http://seewhatever.de/blog/?p=161

class deprecated(object):
    """This is a decorator which can be used to mark functions
    as deprecated. It will result in a warning being emitted
    when the function is used.

    It accepts a single paramter ``msg`` which is shown with the warning.
    It should contain information which function or method to use instead.
    """
    def __init__(self, msg):
        self.msg = msg

    def __call__(self, func):
        def newFunc(*args, **kwargs):
            import warnings
            warnings.warn("Call to deprecated method %r. %s" %
                            (func.__name__, self.msg),
                            category=DeprecationWarning,
                            stacklevel=2)
            return func(*args, **kwargs)
        newFunc.__name__ = func.__name__
        newFunc.__doc__ = func.__doc__
        newFunc.__dict__.update(func.__dict__)
        return newFunc
