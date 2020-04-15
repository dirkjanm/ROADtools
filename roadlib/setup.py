from setuptools import setup, find_namespace_packages
setup(name='roadlib',
      version='0.0.1',
      description='ROADtools common components library',
      author='Dirk-jan Mollema',
      author_email='dirkjan@dirkjanm.io',
      url='https://github.com/dirkjanm/ROADtools/',
      packages=find_namespace_packages(include=['roadtools.*']),
      install_requires=['adal', 'sqlalchemy'],
      zip_safe=False
      )
