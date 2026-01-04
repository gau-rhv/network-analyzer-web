from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network-analyzer",
    version="1.0.0",
    author="Network Security Team",
    description="Network Intrusion Detection System - Network Protocol Analyzer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/network-analyzer",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Internet",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "colorama>=0.4.6",
    ],
)
