from setuptools import setup, find_packages

setup(
    name='redphish',
    version='1.0.0',
    author='Yassine Lasraoui',
    author_email='redX000@users.noreply.github.com',
    description='Advanced Phishing Detection & URL Analyzer',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/redX000/RedPhish',
    packages=find_packages(),
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'redphish=redphish.__main__:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Topic :: Security',
    ],
)
