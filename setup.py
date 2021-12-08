from setuptools import setup

setup(
    name='aiozabbix',
    version='1.1.2',
    description='Asynchronous Zabbix API Python interface',
    url='http://gitlab.com/ModioAB/aiozabbix',
    author='Modio AB',
    author_email='nili@modio.se',
    license='LGPL',
    classifiers=[
        'Framework :: AsyncIO',
        'License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='zabbix monitoring api',
    packages=['aiozabbix'],
    python_requires='>=3.6',
    install_requires=[
        'aiohttp',
    ],
    extras_require={
        'testing': [
            'flake8',
            'pytest',
            'pytest-aiohttp',
            'pytest-cov',
        ]
    }
)
