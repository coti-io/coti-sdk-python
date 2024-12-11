from setuptools import setup

with open("./README.md") as readme:
    long_description = readme.read()

setup(
    name='coti_sdk',
    description='COTI SDK for Privacy Preserving Network',
    long_description=long_description,
    long_description_content_type="text/markdown",
    version='0.0.0',
    license='Apache2.0',
    author="COTI Development",
    author_email='dev@coti.io',
    package_dir={'': '.'},
    url='https://github.com/coti-io/coti-sdk-python',
    keywords=["coti", "privacy", "ethereum", "blockchain", "web3", "garbled-circuits", "l2", "on-chain-compute"],
    install_requires=[
        'pycryptodome==3.19.0', 'cryptography==3.4.8', 'eth-keys>=0.4.0', 'eth-account>=0.13.1'
    ],
    python_requires=">=3.9",
)
