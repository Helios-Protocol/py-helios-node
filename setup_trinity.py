#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup


setup(
    name='helios',
    # *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
    # NOT CURRENTLY APPLICABLE. VERSION BUMPS MANUAL FOR NOW
    version='0.1.0-alpha.2',
    description='The Helios Node',
    author='Tommy Mckinnon',
    author_email='tommy@heliosprotocol.io',
    url='https://github.com/Helios-Protocol/py-helios-node',
    include_package_data=True,
    py_modules=[],
    install_requires=[
        'py-helios-node[helios,hp2p]==0.2.0a18',
    ],
    license='MIT',
    zip_safe=False,
    keywords='blockchain hvm helios',
    packages=[],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
    ],
    # helios
    entry_points={
        'console_scripts': ['helios=helios:main'],
    },
)
