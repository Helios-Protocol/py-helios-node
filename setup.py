#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup, find_packages


deps = { 
    'hvm': [
        "aiohttp>=2.3.1,<4.0.0",
        "async_lru>=0.1.0,<1.0.0",
        "cryptography>=2.0.3,<3.0.0",
        "cytoolz>=0.9.0,<1.0.0",
        "eth-bloom>=1.0.3,<2.0.0",
        "eth-keys>=0.2.0b3,<1.0.0",
        "eth-typing>=2.0.0,<3.0.0",
        "eth-utils>=1.2.0,<2.0.0",
        "lru-dict>=1.1.6",
        "py-ecc>=1.4.2,<2.0.0",
        "pyethash>=0.1.27,<1.0.0",
        "trie>=1.3.5,<2.0.0",
        "sortedcontainers>=2.0.4",
        "pbkdf2>=1.3",
        "rlp-cython>=2.1.5",
    ],
    # The hvm-extra sections is for libraries that the hvm does not
    # explicitly need to function and hence should not depend on.
    # Installing these libraries may make the hvm perform better than
    # using the default fallbacks though.
    'hvm-extra': [
        "coincurve>=8.0.0,<9.0.0",
        "eth-hash[pysha3];implementation_name=='cpython'",
        "eth-hash[pycryptodome];implementation_name=='pypy'",
        "plyvel==1.0.5",
    ],
    'hp2p': [
        "asyncio-cancel-token==0.1.0a2",
        "aiohttp>=2.3.1,<4.0.0",
        "async_lru>=0.1.0,<1.0.0",
        "eth-hash>=0.2.0,<1",
        "netifaces>=0.10.7<1",
        "pysha3>=1.0.0,<2.0.0",
        "upnpclient>=0.0.8,<1",
    ],
    'helios': [
        "async-generator==1.10",
        "bloom-filter==1.3",
        "cachetools>=2.1.0,<3.0.0",
        "coincurve>=8.0.0,<9.0.0",
        "ipython>=6.2.1,<7.0.0",
        "plyvel==1.0.5",
        "helios-web3>=5.0.2",
        "lahja==0.8.0",
        "uvloop==0.11.2;platform_system=='Linux' or platform_system=='Darwin'",
        "websockets>=3.0.0",
    ],
    'test': [
        "hypothesis==3.69.5",
        # pinned to <3.7 until async fixtures work again
        # https://github.com/pytest-dev/pytest-asyncio/issues/89
        "pytest>=3.6,<3.7",
        "pytest-asyncio==0.9.0",
        "pytest-cov==2.5.1",
        "pytest-watch>=4.1.0,<5",
        "pytest-xdist==1.18.1",
        "py-solc==3.2.0",
        "matplotlib",
        # only needed for hp2p
        "pytest-asyncio-network-simulator==0.1.0a2;python_version>='3.6'",
    ],
    'lint': [
        "flake8==3.5.0",
        "mypy==0.620",
    ],
    'benchmark': [
        "termcolor>=1.1.0,<2.0.0",
        "helios-web3>=5.0.2",
    ],
    'doc': [
        "py-evm>=0.2.0-alpha.14",
        "pytest~=3.2",
        # Sphinx pined to `<1.8.0`: https://github.com/sphinx-doc/sphinx/issues/3494
        "Sphinx>=1.5.5,<1.8.0",
        "sphinx_rtd_theme>=0.1.9",
        "sphinxcontrib-asyncio>=0.2.0",
    ],
    'dev': [
        "bumpversion>=0.5.3,<1",
        "wheel",
        "setuptools>=36.2.0",
        "tox==2.7.0",
        "twine",
    ],
}

deps['dev'] = (
    deps['dev'] +
    deps['hvm-extra'] +
    deps['hp2p'] +
    deps['helios'] +
    deps['test'] +
    deps['doc'] +
    deps['lint'] +
    deps['hvm']
)

# As long as hvm, hp2p and helios are managed together in the py-helios-node
# package, someone running a `pip install py-helios-node` should expect all
# dependencies for hvm, hp2p and helios to get installed.
install_requires =  deps['hp2p'] + deps['helios'] + deps['hvm']

setup(
    name='py-helios-node',
    # *IMPORTANT*: Don't manually change the version here. Use the 'bumpversion' utility.
    version='0.3.0',
    description='Python implementation of the Helios Protocol Node',
    long_description_markdown_filename='README.rst',
    author='Tommy Mckinnon',
    author_email='tommy@heliosprotocol.io',
    url='https://github.com/Helios-Protocol/py-helios-node',
    include_package_data=True,
    py_modules=['hvm', 'helios', 'hp2p'],
    install_requires=install_requires,
    extras_require=deps,
    setup_requires=['setuptools-markdown'],
    license='MIT',
    zip_safe=False,
    keywords='helios protocol blockchain node vm',
    packages=find_packages(exclude=["tests", "tests.*"]),
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
