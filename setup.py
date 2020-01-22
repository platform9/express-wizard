"""Install express-wizard"""

from setuptools import setup, find_packages
import os
from os import system 
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

#   def run_cmd(cmd):
#       cmd_stdout = ""
#       tmpfile = "/tmp/pf9.{}.tmp".format(os.getppid())
#       cmd_exitcode = os.system("{} > {} 2>&1".format(cmd, tmpfile))

#       # read output of command
#       if os.path.isfile(tmpfile):
#           try:
#               fh_tmpfile = open(tmpfile, 'r')
#               cmd_stdout = fh_tmpfile.readlines()
#           except:
#               None

#       os.remove(tmpfile)
#       return cmd_exitcode, cmd_stdout


#   clone_express_cli = "git clone {}".format("git@github.com:platform9/express-cli.git")
#   run_cmd(clone_express_cli)
#   #system("{}".format(clone_express_cli)) 

#   print("cwd: {}".format(os.system("pwd")))
#   switch_branch = "cd {} && git checkout {}".format("express-cli", "tomchris/setuptools")
#   #system("{}".format(switch_branch)) 
#   run_cmd(switch_branch)

#   install_cli = "cd {} && pip install -e .".format("express-cli")
#   #system("{}".format(install_cli)) 
#   run_cmd(install_cli)

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
#    dependency_links=[
#        ''.join(['file:\\', os.path.join(os.getcwd(), 'express-cli#egg=express-cli')])
#        ],
    install_requires=[
        'requests',
        'urllib3',
        'prettytable',
        'argparse',
        'pprint',
        'openstacksdk==0.12.0',
        'express-cli @ git+git://github.com/platform9/express-cli.git@tomchris/restructure#egg=express-cli',
        ],
    entry_points = {
        'console_scripts': [
            'wizard=wizard:main',
            ],
    }, 
)
