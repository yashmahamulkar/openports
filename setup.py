from setuptools import setup, find_packages
import os
import re


def read_version():
    here = os.path.dirname(__file__)
    with open(os.path.join(here, "openports", "__init__.py"), encoding="utf-8") as fh:
        match = re.search(r'^__version__\s*=\s*"([^"]+)"', fh.read(), re.MULTILINE)
    if not match:
        raise RuntimeError("Unable to find __version__ in openports/__init__.py")
    return match.group(1)


# Read README for long description
def read_readme():
    try:
        with open("README.md", "r", encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return """
# OpenPorts 🔍⚡

**Lightning-fast port scanner and process manager for developers**

Stop wondering what's running on your ports. OpenPorts gives you instant visibility into your system's network activity with beautiful, actionable insights.

## ✨ Features
- 🚀 **Blazing Fast**: Optimized algorithms for instant port discovery
- 🎯 **Smart Filtering**: Find exactly what you're looking for
- 💀 **Process Control**: Kill processes with confidence
- 🎨 **Beautiful Output**: Rich terminal UI (when available)
- 🔧 **Developer Friendly**: Perfect for debugging and development
- 🌍 **Cross Platform**: Works on Windows, macOS, and Linux

## Quick Start
```bash
pip install openports
openports              # List all listening ports
openports -p 3000      # Check specific port
openports -s react     # Find React processes
openports -k 3000      # Kill process on port 3000
```

Perfect for developers, DevOps engineers, and anyone who needs to understand their system's network activity.
        """

VERSION = read_version()
DESCRIPTION = '🔍⚡ Lightning-fast port scanner and process manager'
LONG_DESCRIPTION = read_readme()

# Requirements for different use cases
INSTALL_REQUIRES = []

EXTRAS_REQUIRE = {
    'fast': ['psutil>=5.8.0'],
    'rich': ['rich>=10.0.0'],
    'full': ['psutil>=5.8.0', 'rich>=10.0.0'],
    'dev': [
        'psutil>=5.8.0', 
        'rich>=10.0.0',
        'pytest>=6.0',
        'pytest-cov>=2.0',
        'black>=21.0',
        'flake8>=3.9',
    ]
}

setup(
    name="openports",
    version=VERSION,
    author="Yash Mahamulkar",
    author_email="ymmahamulkar@gmail.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    url="https://github.com/yashmahamulkar/openports",  # Add your actual repo URL
    project_urls={
        "Bug Reports": "https://github.com/yashmahamulkar/openports/issues",
        "Source": "https://github.com/yashmahamulkar/openports",
        "Documentation": "https://github.com/yashmahamulkar/openports#readme",
    },
    packages=find_packages(),
    include_package_data=True,
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            'openports=openports.cli:main',
            'list-ports=openports.cli:main',  # Alternative command name
        ],
    },
    keywords=[
        'port scanner', 'network tools', 'process manager', 'developer tools',
        'network debugging', 'port checker', 'system administration', 'devops',
        'tcp', 'udp', 'listening ports', 'process killer', 'network monitoring',
        'cross-platform', 'command line', 'terminal', 'sysadmin'
    ],
    classifiers=[
        # Development Status
        "Development Status :: 5 - Production/Stable",
        
        # Audience
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        
        # Topics
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Utilities",
        "Topic :: System :: Networking",
        "Topic :: Internet",
        
        # License
        "License :: OSI Approved :: MIT License",
        
        # Programming Language
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        
        # Operating Systems
        "Operating System :: OS Independent",
        "Operating System :: POSIX :: Linux",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
        
        # Environment
        "Environment :: Console",
        "Environment :: Console :: Curses",
        
        # Natural Language
        "Natural Language :: English",
    ],
    zip_safe=False,
    platforms=["any"],
)