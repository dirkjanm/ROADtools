from setuptools import setup, find_namespace_packages
setup(name='roadlib',
      version='1.3.0',
      description='ROADtools common components library',
      author='Dirk-jan Mollema',
      author_email='dirkjan@outsidersecurity.nl',
      url='https://github.com/dirkjanm/ROADtools/',
      license='MIT',
      classifiers=[
          'Intended Audience :: Information Technology',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
      ],
      packages=find_namespace_packages(include=['roadtools.*']),
      install_requires=['requests', 'cryptography', 'sqlalchemy>=1.4', 'pyjwt>=2.0'],
      extras_require={
        "async": ["aiohttp"],
      },
      zip_safe=False
      )
