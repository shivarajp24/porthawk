from setuptools import setup, find_packages

setup(
    name="porthawk",
    version="2.0.0",
    description="Fast multi-threaded port scanner - Nmap alternative",
    author="shivarajp24",
    packages=find_packages(),
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "porthawk=portscanner.cli:main",
        ],
    },
)
