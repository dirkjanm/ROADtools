from setuptools import setup
setup(name='roadrecon',
      version='0.0.1',
      description='Azure AD recon for red/blue',
      author='Dirk-jan Mollema',
      author_email='dirkjan@dirkjanm.io',
      url='https://github.com/dirkjanm/ROADtools/',
      packages=['roadtools.roadrecon', 'roadtools.roadrecon.plugins'],
      install_requires=['roadlib', 'flask', 'sqlalchemy', 'marshmallow', 'flask-sqlalchemy', 'flask-marshmallow', 'flask-cors', 'marshmallow-sqlalchemy', 'aiohttp'],
      zip_safe=False,
      include_package_data=True,
      entry_points={
          'console_scripts': ['roadrecon-gui=roadtools.roadrecon.server:main',
                              'roadrecon=roadtools.roadrecon.main:main']
      }
      )
