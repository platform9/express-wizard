"""Install express-wizard"""

from setuptools import setup, find_packages
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    # $ pip install express-wizard
    #
    name='express-wizard', #REQUIRED
    version='0.0.1', #REQUIRED
    description='Wizard for Platform9 express-cli and pf9-express', #OPTIONAL
    long_description=long_description, #OPTIONAL
    long_description_content_type='text/markdown',  #OPTIONAL
    url='https://github.com/Platform9/express-wizard',  #OPTIONAL
    author='Thomas Christopoulos',  #OPTIONAL
    author_email='tom.christopoulos@platform9.com',  #OPTIONAL
    classifiers=[  # Optional
	'Development Status :: 3 - Alpha',
	'Intended Audience :: Developers',
	'Topic :: Software Development :: Build Tools',
	'License :: OSI Approved :: Apache Software License',
	'Programming Language :: Python :: 2',
	'Programming Language :: Python :: 2.7',
	'Programming Language :: Python :: 3',
	'Programming Language :: Python :: 3.5',
	'Programming Language :: Python :: 3.6',
    ],
    packages=find_packages(exclude=['docs', 'tests*']),
    #packages=find_packages() + find_packages(where='./lib'),  # Required
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, <4',
    dependency_links=['http://github.com/platform9/express-cli/tarball/master#egg=express-cli']
    install_requires=[
        'requests',
        'urllib3',
        'prettytable',
        'argparse',
        'pprint',
        'openstacksdk==0.12.0',
        #'express-cli @ git+git://github.com/platform9/express-cli.git@master',
        ],
    entry_points = {
        'console_scripts': [
            'wizard=wizard:main',
            ],
    }, 
)
