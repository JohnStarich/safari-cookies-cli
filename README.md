# Safari Cookies CLI

A CLI for parsing and searching Safari's cookies.

The original cookie parser was designed and written by Satishb3.
I used their [blog post](http://www.securitylearn.net/2012/10/27/cookies-binarycookies-reader/) and their [source code](http://securitylearn.net/wp-content/uploads/tools/iOS/BinaryCookieReader.py) as a starting point for this project.

## Example usage

```bash
# Show CLI usage and option descriptions
./safari_cookies.py --help

# Show all cookies in default macOS cookie location
./safari_cookies.py
# Show all cookies in a specified cookie file
./safari_cookies.py -f ~/Library/Cookies/Cookies.binarycookies

# Show all cookies for github.com
./safari_cookies.py -u github.com
# Show all cookies for github.com, including expired cookies
./safari_cookies.py -u github.com -e

# Show only user session cookie for github.com
./safari_cookies.py -u github.com -n user_session
# Show user session cookie in JSON format (for consumption by other tools)
./safari_cookies.py -u github.com -n user_session -o json
```
