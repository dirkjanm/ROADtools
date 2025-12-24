from setuptools import setup
setup(name='roadtx',
      version='1.21.1',
      description='ROADtools Token eXchange',
      author='Dirk-jan Mollema',
      author_email='dirkjan@outsidersecurity.nl',
      url='https://github.com/dirkjanm/ROADtools/',
      license='MIT',
      classifiers=[
          'Intended Audience :: Information Technology',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
          'Programming Language :: Python :: 3.13',
      ],
      packages=['roadtools.roadtx'],
      package_data={'roadtools.roadtx': ['firstpartyscopes.json']},
      install_requires=[
          'roadlib>=1.6',
          'requests',
          'selenium',
          'selenium-wire-roadtx',
          'pyotp',
          'pycryptodomex',
          'signxml>3',
          'setuptools'
      ],
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['roadtx=roadtools.roadtx.main:main',]
      }
      )
