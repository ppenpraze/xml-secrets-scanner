"""Setup file for xml-secrets-scanner plugins."""

from setuptools import setup, find_packages

setup(
    name='xml-secrets-scanner',
    version='1.0.0',
    description='Custom detect-secrets plugins for XML password and Unix crypt detection with entity filtering',
    author='Your Name',
    url='https://github.com/ppenpraze/xml-secrets-scanner',
    py_modules=['xml_plugins'],
    install_requires=[
        'detect-secrets>=1.4.0',
    ],
    entry_points={
        'detect_secrets.plugins': [
            'xml_password = xml_plugins:XMLPasswordPlugin',
            'unix_crypt = xml_plugins:UnixCryptPlugin',
        ],
    },
    python_requires='>=3.6',
)
