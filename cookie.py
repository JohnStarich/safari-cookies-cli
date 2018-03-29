from time import strftime, gmtime, time


class Cookie(object):
    def __init__(self, name, value, url, path, create_epoch, expiry_epoch,
                 cookie_flags):
        self.name = name
        self.value = value
        self.url = url
        self.path = path
        self.create_epoch = create_epoch
        self.expiry_epoch = expiry_epoch
        self.cookie_flags = cookie_flags

    @staticmethod
    def _epoch_to_date(epoch_time):
        return strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(epoch_time))

    @property
    def create_date(self):
        return Cookie._epoch_to_date(self.create_epoch)

    @property
    def expiry_date(self):
        return Cookie._epoch_to_date(self.expiry_epoch)

    @property
    def expired(self):
        return self.expired_by_time(time())

    def expired_by_time(self, timestamp):
        return self.expiry_epoch - timestamp < 0

    def __str__(self):
        return (
            "Cookie : {name}={value}; domain={url}; path={path}; "
            "expires={expiry_date}; {cookie_flags}"
        ).format(
             name=self.name, value=self.value, url=self.url,
             path=self.path, expiry_date=self.expiry_date,
             cookie_flags=self.cookie_flags,
        )

    def to_dict(self, more=False):
        data = {
            'name': self.name,
            'value': self.value,
            'url': self.url,
            'path': self.path,
            'create_date': self.create_date,
            'expiry_date': self.expiry_date,
            'cookie_flags': self.cookie_flags,
        }
        if more is True:
            data.update({
                'create_epoch': self.create_epoch,
                'expiry_epoch': self.expiry_epoch,
                'expired': self.expired,
            })
        return data
