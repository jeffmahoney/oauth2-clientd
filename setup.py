#!/usr/bin/python3
# vim: sw=4 ts=4 et si:
"""
Setup file for installation
"""

from setuptools import setup

setup(
    package_data={'oauth2_clientd': ['data/*.conf']}
)
