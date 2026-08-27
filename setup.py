"""Legacy editable-install entrypoint for the pip version deployed on RHEL 8."""

from setuptools import find_packages, setup


setup(
    name="rules-recertify",
    version="0.1.0",
    description="Illumio rule recertification collection and reporting",
    python_requires=">=3.9",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[],
    extras_require={"reporting": ["openpyxl>=3.0"]},
    entry_points={"console_scripts": ["rules-recertify=rules_recertify.cli:main"]},
)
