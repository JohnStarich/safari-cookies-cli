#!/usr/bin/env python3

from io import BytesIO
from struct import unpack
from time import strftime, gmtime
import argparse
import json
import os
import sys

from cookie import Cookie


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file-path',
                        default='~/Library/Cookies/Cookies.binarycookies',
                        help='The full path to Cookies.binarycookies')
    parser.add_argument('-u', '--url', type=str,
                        help='Filter for the given URL')
    parser.add_argument('-o', '--output-format', choices=['text', 'json'],
                        default='text', help='The output format for cookies.')

    args = parser.parse_args()
    expanded_path = os.path.expanduser(args.file_path)
    with open(expanded_path, 'rb') as binary_file:
        cookies = parse_cookies(binary_file)
        if args.url is not None:
            cookies = filter(lambda c: args.url in c.url, cookies)

        if args.output_format == 'text':
            for cookie in cookies:
                print(cookie)
        elif args.output_format == 'json':
            json_cookies = map(lambda c: c.to_dict(), cookies)
            print(json.dumps(list(json_cookies)))


def parse_cookies(binary_file):
    file_header = binary_file.read(4)  # File Magic String:cook

    if file_header != b'cook':
        print("Not a Cookies.binarycookie file")
        sys.exit(1)

    # Number of pages in the binary file: 4 bytes
    num_pages = unpack('>i', binary_file.read(4))[0]

    page_sizes = []
    for np in range(num_pages):
        # Each page size: 4 bytes*number of pages
        page_sizes.append(unpack('>i', binary_file.read(4))[0])

    pages = []
    for ps in page_sizes:
        # Grab individual pages and each page will contain >= one cookie
        pages.append(binary_file.read(ps))

    cookies = []

    for page in pages:
        # Converts the string to a file. So that we can use read/write
        # operations easily.
        page = BytesIO(page)
        page.read(4)  # page header: 4 bytes: Always 00000100
        # Number of cookies in each page, first 4 bytes after the page header
        # in every page.
        num_cookies = unpack('<i', page.read(4))[0]

        cookie_offsets = []
        for nc in range(num_cookies):
            # Every page contains >= one cookie. Fetch cookie starting point
            # from page starting byte
            cookie_offsets.append(unpack('<i', page.read(4))[0])

        page.read(4)  # end of page header: Always 00000000

        cookie = ''
        for offset in cookie_offsets:
            # Move page pointer to the cookie starting point
            page.seek(offset)
            # fetch cookie size
            cookiesize = unpack('<i', page.read(4))[0]
            # read the complete cookie
            cookie = BytesIO(page.read(cookiesize))

            cookie.read(4)  # unknown

            # Cookie flags:  1=secure, 4=httponly, 5=secure+httponly
            flags = unpack('<i', cookie.read(4))[0]
            cookie_flags = ''
            if flags == 0:
                cookie_flags = ''
            elif flags == 1:
                cookie_flags = 'Secure'
            elif flags == 4:
                cookie_flags = 'HttpOnly'
            elif flags == 5:
                cookie_flags = 'Secure; HttpOnly'
            else:
                cookie_flags = 'Unknown'

            cookie.read(4)  # unknown

            # cookie domain offset from cookie starting point
            urloffset = unpack('<i', cookie.read(4))[0]
            # cookie name offset from cookie starting point
            nameoffset = unpack('<i', cookie.read(4))[0]
            # cookie path offset from cookie starting point
            pathoffset = unpack('<i', cookie.read(4))[0]
            # cookie value offset from cookie starting point
            valueoffset = unpack('<i', cookie.read(4))[0]

            endofcookie = cookie.read(8)  # end of cookie

            # Expiry date is in Mac epoch format: Starts from 1/Jan/2001
            expiry_date_epoch = unpack('<d', cookie.read(8))[0] + 978307200
            # 978307200 is unix epoch of  1/Jan/2001
            # [:-1] strips the last space
            expiry_date = strftime("%a, %d %b %Y ",
                                   gmtime(expiry_date_epoch))[:-1]

            # Cookies creation time
            create_date_epoch = unpack('<d', cookie.read(8))[0] + 978307200
            create_date = strftime("%a, %d %b %Y ",
                                   gmtime(create_date_epoch))[:-1]
            # print(create_date)

            cookie.seek(urloffset - 4)  # fetch domaain value from url offset
            url = ''
            u = cookie.read(1)
            while unpack('<b', u)[0] != 0:
                url = url + u.decode()
                u = cookie.read(1)

            cookie.seek(nameoffset - 4)  # fetch cookie name from name offset
            name = ''
            n = cookie.read(1)
            while unpack('<b', n)[0] != 0:
                name = name + n.decode()
                n = cookie.read(1)

            cookie.seek(pathoffset - 4)  # fetch cookie path from path offset
            path = ''
            pa = cookie.read(1)
            while unpack('<b', pa)[0] != 0:
                path = path + pa.decode()
                pa = cookie.read(1)

            # fetch cookie value from value offset
            cookie.seek(valueoffset - 4)
            value = ''
            va = cookie.read(1)
            while unpack('<b', va)[0] != 0:
                value = value + va.decode()
                va = cookie.read(1)

            cookies.append(Cookie(
                name=name, value=value, url=url, path=path,
                expiry_date=expiry_date, cookie_flags=cookie_flags,
            ))

    return cookies


if __name__ == '__main__':
    main()
