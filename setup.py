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
    url='https://github.com/sinner-/shsmd',
    author='Sina Sadeghi',
    install_requires=['Click>=6.7',
                      'Flask-RESTful>=0.3.5',
                      'PyMySQL>=0.7.10',
                      'PyNaCl>=1.0.1'],
    description='Self Hosted Secure Messaging Daemon',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'shsmd-api = shsmd.cmd.api:main',
            'shsmd-manage = shsmd.cmd.manage:main'
        ]},
    tests_require=['tox'],
    cmdclass = {'test': Tox},
)
