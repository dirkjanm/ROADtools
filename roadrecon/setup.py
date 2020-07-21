from setuptools import setup
setup(name='roadrecon',
      version='0.9.0',
      description='Azure AD recon for red/blue',
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
      ],
      packages=['roadtools.roadrecon', 'roadtools.roadrecon.plugins'],
      install_requires=['roadlib', 'flask', 'sqlalchemy', 'marshmallow', 'flask-sqlalchemy', 'flask-marshmallow', 'flask-cors', 'marshmallow-sqlalchemy>=0.22', 'aiohttp'],
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['roadrecon-gui=roadtools.roadrecon.server:main',
                              'roadrecon=roadtools.roadrecon.main:main']
      }
      )
