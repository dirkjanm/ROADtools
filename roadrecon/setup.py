from setuptools import setup
setup(name='roadrecon',
      version='1.6.0',
      description='Azure AD recon for red and blue',
      author='Dirk-jan Mollema',
      author_email='dirkjan@dirkjanm.io',
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
      packages=['roadtools.roadrecon', 'roadtools.roadrecon.plugins'],
      package_data={'roadtools.roadrecon.plugins': ['*.yaml']},
      install_requires=[
          'roadlib>=0.21',
          'flask<3',
          'sqlalchemy>=1.4',
          'marshmallow',
          'flask-sqlalchemy>=3.1.1',
          'flask-marshmallow',
          'flask-cors',
          'marshmallow-sqlalchemy>=1.0.0',
          'aiohttp',
          'openpyxl'
      ],
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['roadrecon-gui=roadtools.roadrecon.server:main',
                              'roadrecon=roadtools.roadrecon.main:main']
      }
      )
