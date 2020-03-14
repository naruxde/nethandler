#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Setup script for nethandler module."""
__author__ = "Sven Sager"
__copyright__ = "Copyright (C) 2019 Sven Sager"
__license__ = "LGPLv3"
from setuptools import setup

setup(
    version='0.1.1',

    packages=['nethandler'],
    python_requires="~=3.4",
    keywords="network command socket",

    # Additional meta-data
    name='nethandler',
    author='Sven Sager',
    author_email='akira@hokage.de',
    maintainer="Sven Sager",
    maintainer_email="akira@hokage.de",
    url='https://revpimodio.org',
    description='Call functions on a server',
    long_description="",
    download_url="",
    classifiers=[
        "Development Status :: 1 - Planning",
        # "Development Status :: 2 - Pre-Alpha",
        # "Development Status :: 3 - Alpha",
        # "Development Status :: 4 - Beta",
        # "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Networking",
    ],
    license='LGPLv3',
)
