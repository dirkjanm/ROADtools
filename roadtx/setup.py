from setuptools import setup
setup(name='roadtx',
      version='1.17.0',
      description='ROADtools Token eXchange',
      author='Dirk-jan Mollema',
      author_email='dirkjan@outsidersecurity.nl',
      url='https://github.com/dirkjanm/ROADtools/',
      license='MIT',
      classifiers=[
          'Intended Audience :: Information Technology',
          'License :: OSI Approved :: MIT License',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
      ],
      packages=['roadtools.roadtx'],
      package_data={'roadtools.roadtx': ['firstpartyscopes.json']},
      install_requires=[
          'roadlib>=1.3',
          'requests',
          'selenium',
          'selenium-wire',
          'pyotp',
          'pycryptodomex',
          'signxml>3',
          'setuptools',
          'blinker<1.8.0'
      ],
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['roadtx=roadtools.roadtx.main:main',]
      }
      )
