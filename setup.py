from setuptools import setup, find_packages

def readme():
  with open("README.md") as f:
    return f.read()

setup(
  name = "yAuth",
  version = "0.1.0",
  description = "sanic-jwt extensions for yRest",
  long_description = readme(),
  long_description_content_type='text/markdown',
  classifiers = [
    "Development Status :: 4 - Beta",
    "Environment :: Plugins",
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
  packages = find_packages(),
  python_requires=">=3.6",
  install_requires = [
    "pyJWT",
    "ySanic",
    "yModel"
  ],
  test_suite = "unittest"
)
