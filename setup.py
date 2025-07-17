"""
Setup script for Encryptly SDK
"""

from setuptools import setup, find_packages

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="encryptly",
    version="0.1.1",
    author="Encryptly Team",
    author_email="support@encryptly.com",
    description="Lightweight Authentication for AI Agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/encryptly-sdk",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/encryptly-sdk/issues",
        "Documentation": "https://docs.encryptly.com",
        "Source Code": "https://github.com/yourusername/encryptly-sdk",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Security :: Cryptography",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    python_requires=">=3.8",
    install_requires=[
        "PyJWT>=2.8.0",
        "cryptography>=41.0.0",
        "typing-extensions>=4.7.0; python_version < '3.9'",
        "argcomplete>=3.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
            "pre-commit>=3.0",
        ],
        "docs": [
            "sphinx>=5.0",
            "sphinx-rtd-theme>=1.2",
            "myst-parser>=2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "encryptly=encryptly.cli:main",
        ],
    },
    include_package_data=True,
    keywords=[
        "ai",
        "agents",
        "authentication",
        "security",
        "crewai",
        "langchain",
        "multi-agent",
        "jwt",
        "cryptography",
        "authorization",
        "sdk",
        "api",
    ],
    zip_safe=False,
) 