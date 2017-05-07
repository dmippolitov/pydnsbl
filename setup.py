#!/usr/bin/env python3
from distutils.core import setup
from setuptools import find_packages

import os
import sys

requirements = [
    'aiodns',
]


setup(
    name='pydnsbl',
    version='0.1',
    description='Async dnsbl lists checker based on asyncio/aiodns.',
    url='https://github.com/dmippoltiov/pydnsbl/',

    author=u'Dmitry ippolitov',
    author_email='ippolitov87@gmail.com',

    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=requirements,
)
