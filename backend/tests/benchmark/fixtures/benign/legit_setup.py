"""Benign: Standard setup.py for a Python package."""
from setuptools import setup, find_packages

setup(
    name="my-awesome-lib",
    version="2.1.0",
    description="A helpful utility library",
    author="Developer",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "pydantic>=2.0",
    ],
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
)
