#!/usr/bin/env python3
"""Setup script for PatchVerify"""
from setuptools import setup, find_packages

setup(
    name="patchverify",
    version="0.1.0",
    description="Verify whether a software update actually fixed what it promised",
    author="PatchVerify Team",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=[
        "flask>=3.0.0",
        "requests>=2.31.0",
        "PyJWT>=2.8.0",
        "click>=8.1.0",
    ],
    entry_points={
        "console_scripts": [
            "patchverify=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
