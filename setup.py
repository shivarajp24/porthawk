from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="porthawk",
    version="2.0.4",
    description="Fast multi-threaded port scanner - Nmap alternative",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="shivarajp24",
    url="https://github.com/shivarajp24/porthawk",
    packages=find_packages(),
    python_requires=">=3.10",
    keywords="port-scanner nmap-alternative network security",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    entry_points={
        "console_scripts": [
            "porthawk=portscanner.cli:main",
        ],
    },
)
