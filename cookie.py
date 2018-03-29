
class Cookie(object):
    def __init__(self, name, value, url, path, expiry_date, cookie_flags):
        self.name = name
        self.value = value
        self.url = url
        self.path = path
        self.expiry_date = expiry_date
        self.cookie_flags = cookie_flags

    def __str__(self):
        return (
            "Cookie : {name}={value}; domain={url}; path={path}; "
            "expires={expiry_date}; {cookie_flags}"
        ).format(
             name=self.name, value=self.value, url=self.url,
             path=self.path, expiry_date=self.expiry_date,
             cookie_flags=self.cookie_flags,
        )

    def to_dict(self):
        return self.__dict__
