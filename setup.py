from setuptools import setup

def readme():
  with open("README.md") as f:
    return f.read()

setup(
  name = "yAuth",
  version = "0.0.1",
  description = "sanic-jwt extensions for yRest",
  long_description = readme(),
  classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Plugins",
    "Framework :: ySanic",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Topic :: Security"
  ],
  keywords = "auth yRest",
  url = "https://github.com/Garito/yAuth",
  author = "Garito",
  author_email = "garito@gmail.com",
  license = "MIT",
  packages = ["yAuth"],
  install_requires = [
    "sanic-jwt",
    "ySanic",
    "yModel"
  ],
  dependency_links = [
    "git+https://github.com/Garito/yModel#egg=yModel",
    "git+https://github.com/Garito/ySanic#egg=ySanic"
  ],
  test_suite = "unittest"
)
