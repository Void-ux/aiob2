import re
from setuptools import setup


with open('README.md') as f:
    readme = f.read()

with open('aiob2/__init__.py') as f:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', f.read(), re.MULTILINE).group(1)

setup(
    name='aiob2',
    author='Dan',
    author_email='the.void.altacc@gmail.com',
    url='https://github.com/Void-ux/aiob2/',
    project_urls={
        'Issue Tracker': 'https://github.com/Void-ux/aiob2/issues/',
    },
    version=version,
    packages=['aiob2'],
    license='GNU GPLv3',
    description="A simple and easy to use async wrapper for Backblaze's B2 bucket API.",
    long_description=readme,
    long_description_content_type='text/markdown',
    python_requires='>=3.8.10',
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ]
)
