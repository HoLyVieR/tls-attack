from setuptools import setup, find_packages

setup(
    name = "tls-attack",
    packages = find_packages(exclude=['docs', 'tests', 'tests.*']),
    version = "0.1",
    description = "Library that contains various SSL/TLS utilities to help build proof of concept TLS attack.",
    author = "Olivier Arteau",
    author_email = "arteau.olivier@gmail.com"
)