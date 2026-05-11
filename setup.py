#!/usr/bin/env python3
# setup.py — fallback for older pip / tools that don't support pyproject.toml

from setuptools import setup, find_packages

setup(
    name             = "cybershield",
    version          = "1.0.0",
    description      = "Defensive cybersecurity toolkit with GUI and CLI",
    long_description = open("README.md", encoding="utf-8").read(),
    long_description_content_type = "text/markdown",
    python_requires  = ">=3.10",

    packages = find_packages(),

    package_data = {
        "cybershield": [
            "gui/styles/*.qss",
            "config.py",
        ],
    },

    install_requires = [
        "rich>=13.0",
        "flask>=3.0",
        "pyngrok>=7.0",
        "qrcode[pil]>=7.4",
        "paramiko>=3.0",
        "reportlab>=4.0",
        "PyQt6>=6.6",
        "requests>=2.31",
        "scapy>=2.5",
    ],

    entry_points = {
        "console_scripts": [
            "cybershield = cybershield.__main__:main",
        ],
    },

    classifiers = [
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Environment :: Console",
        "Environment :: X11 Applications :: Qt",
    ],
)
