from setuptools import setup, find_namespace_packages

setup(
    name="qryptx",
    version="0.1.0",
    packages=find_namespace_packages(include=["qryptx", "qryptx.*"]),
    include_package_data=True,
    install_requires=[
        "paramiko>=3.4.0",
        "pyOpenSSL>=24.0.0",
        "pycryptodome>=3.19.1",
        "python-telegram-bot>=20.7",
        "pyfiglet>=1.0.2",
        "pyTelegramBotAPI>=4.15.2"
    ],
    dependency_links=[
        "git+https://github.com/open-quantum-safe/liboqs-python.git#egg=liboqs-python"
    ]
)