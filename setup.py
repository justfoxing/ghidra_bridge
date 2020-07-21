import setuptools
import subprocess

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="ghidra_bridge",
    version=subprocess.check_output("git describe", shell=True).decode("utf-8").strip(),
    author="justfoxing",
    author_email="justfoxingprojects@gmail.com",
    description="RPC bridge from Python to Ghidra Jython",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/justfoxing/ghidra_bridge",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "jfx_bridge>0.4.1"
    ],
)