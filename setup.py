import os
from setuptools import setup, find_packages


main_ns = {}
ver_path = os.path.join(os.path.dirname(__file__), 'cowayaio', '__version__.py')
with open(ver_path) as ver_file:
    exec(ver_file.read(), main_ns)

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cowayaio",
    version=main_ns["__version__"],
    author="Robert Drinovac",
    author_email="unlisted@gmail.com",
    description="A asynchronous python library for Coway Air Purifiers ",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/RobertD502/cowayaio',
    keywords='coway, iocare, iocare api, coway api, airmega',
    packages=find_packages(),
    python_requires= ">=3.8",
    install_requires=[
        "aiohttp>=3.8.1",
        "beautifulsoup4>=4.11.1"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent"
    ],
    project_urls={  # Optional
    'Bug Reports': 'https://github.com/RobertD502/cowayaio/issues',
    'Source': 'https://github.com/RobertD502/cowayaio/',
    },
)
