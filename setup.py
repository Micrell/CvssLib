from setuptools import setup, find_packages


setup(name='cvss-lib',
      version='0.0.1',
      description='A librairy with python class to manipulate CVSS',
      author="Jules PETRY",
      author_email="jules67117@gmail.com",
      packages=find_packages(exclude=['test']),
      install_requires=["numpy"],
      license="MIT")