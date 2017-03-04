""" shsmd
"""

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import sys

class Tox(TestCommand):
    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True
    def run_tests(self):
        #import here, cause outside the eggs aren't loaded
        import tox
        errcode = tox.cmdline(self.test_args)
        sys.exit(errcode)

setup(
    name='shsmd',
    version='1.0',
    url='https://github.com/sinner-',
    author='Sina Sadeghi',
    install_requires=['aniso8601>=1.1.0',
                      'astroid>=1.4.4',
                      'cffi>=1.5.0',
                      'colorama>=0.3.6',
                      'Flask>=0.10.1',
                      'PyMySQL>=0.7.4',
                      'Flask-RESTful>=0.3.5',
                      'itsdangerous>=0.24',
                      'Jinja2>=2.8',
                      'lazy-object-proxy>=1.2.1',
                      'MarkupSafe>=0.23',
                      'pycparser>=2.14',
                      'virtualenv>=15.0.1',
                      'PyNaCl>=0.3.0',
                      'python-dateutil>=2.4.2',
                      'pytz>=2015.7',
                      'six>=1.10.0',
                      'Werkzeug>=0.11.3',
                      'Click>=6.7',
                      'wrapt>=1.10.6'],
    description='Self Hosted Secure Messaging Daemon',
    packages=find_packages(),
    package_data={'': ['../schema.sql']},
    entry_points={
        'console_scripts': [
            'shsmd-api = shsmd.cmd.api:main',
            'shsmd-manage = shsmd.cmd.manage:main'
        ]},
    tests_require=['tox'],
    cmdclass = {'test': Tox},
)
