""" shsmd
"""

from setuptools import setup

setup(
    name='shsmd',
    version='1.0',
    url='https://github.com/sinner-',
    author='Sina Sadeghi',
    install_requires=['aniso8601==1.1.0',
                      'astroid==1.4.4',
                      'cffi==1.5.0',
                      'colorama==0.3.6',
                      'Flask==0.10.1',
                      'Flask-RESTful==0.3.5',
                      'itsdangerous==0.24',
                      'Jinja2==2.8',
                      'lazy-object-proxy==1.2.1',
                      'MarkupSafe==0.23',
                      'pycparser==2.14',
                      'pylint==1.5.4',
                      'PyNaCl==0.3.0',
                      'python-dateutil==2.4.2',
                      'pytz==2015.7',
                      'six==1.10.0',
                      'Werkzeug==0.11.3',
                      'wrapt==1.10.6'],
    description='Self Hosted Secure Messaging Daemon',
    packages=['shsmd'],
    package_data={'': ['../schema.sql']},
    entry_points={
        'console_scripts': [
            'shsmd = shsmd.__main__:main'
        ]},
)
