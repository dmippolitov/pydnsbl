#!/usr/bin/env python3
from distutils.core import setup
from setuptools import find_packages

import os
import sys

def get_long_description():
    path = os.path.join(os.path.dirname(__file__), 'README.md')
    with open(path) as f:
        return f.read() 

requirements = [
    'aiodns>=1.1.1,<=2.0',
    'idna>=2.9,<3'
]


setup(
    name='pydnsbl',
    version='1.0.4',
    description='Async dnsbl lists checker based on asyncio/aiodns.',
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/dmippolitov/pydnsbl/',

    author=u'Dmitry ippolitov',
    author_email='ippolitov87@gmail.com',
    license='MIT',

    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=requirements,
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Topic :: Utilities',
    ],
)
