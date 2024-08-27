# Copyright (c), CommunityLogiq Software

import setuptools
import os

setuptools.setup(
    name="ulsdk",
    version=os.getenv("PY_PACKAGE_VERSION"),
    author="Max Burke",
    author_email="max@urbanlogiq.com",
    description="UrbanLogiq SDK",
    packages=setuptools.find_packages(),
    python_requires=">=3.12",
    install_requires=[
        "flatbuffers",
        "pyarrow",
        "pynacl",
        "requests",
    ],
)
