#!/usr/bin/env python3

# python3 setup.py sdist --format=zip,gztar

import sys

from codecs import open
from os import path
from setuptools import setup, find_packages

def load(module_name, file_path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules[module_name] = module

here = path.abspath(path.dirname(__file__))

# Load the version module to get the version number
load('version', path.join(here, 'seed_phrases_for_stellar/version.py'))
import version

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

if sys.version_info[:3] < (3, 4, 0):
    sys.exit('Error: seed-phrases-for-stellar requires Python'
             ' version >= 3.4.0...')

setup(
    name='seed-phrases-for-stellar',
    version=version.__version__,
    description='Utility for generating Stellar accounts from BIP39/Electrum seed phrases',
    long_description=long_description,
    url='https://github.com/reverbel/seed-phrases-for-stellar',
    author='Francisco Reverbel',
    author_email='reverbel@gmail.com',
    license="http://opensource.org/licenses/MIT",
    keywords='Stellar deterministic keypair generation '
             'BIP39 Electrum mnemonic seed phrase',
    packages=['seed_phrases_for_stellar'],    
    install_requires=[
        'mnemonic>=0.18',
        'pbkdf2>=1.3',
        'stellar-base>=0.1.5',
    ],
    entry_points={
        'console_scripts': [
                'seed-phrase-to-stellar-keys'
                '=seed_phrases_for_stellar.seed_phrase_to_stellar_keys:main',
        ]
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Topic :: Utilities',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',        
    ],
)
