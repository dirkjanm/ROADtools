from setuptools import setup
setup(name='roadtx',
      version='1.0.0',
      description='Azure AD Token eXchange',
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
      install_requires=[
          'roadlib>=0.14',
          'requests',
          'selenium',
          'selenium-wire',
          'pyotp',
          'pycryptodomex'
      ],
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['roadtx=roadtools.roadtx.main:main',]
      }
      )
