# ROADtools 
*(**R**ogue **O**ffice 365 and **A**zure (active) **D**irectory tools)*

![Python 3 only](https://img.shields.io/badge/python-3.6+-blue.svg)
![License: MIT](https://img.shields.io/pypi/l/roadlib.svg)

<img src="roadrecon/frontend/src/assets/rt_transparent.svg" width="300px" alt="ROADtools logo" />

ROADtools is a framework to interact with Azure AD. It currently consists of a library (roadlib) and the ROADrecon Azure AD exploration tool.

## ROADlib
![PyPI version](https://img.shields.io/pypi/v/roadlib.svg)

ROADlib is a library that can be used to authenticate with Azure AD or to build tools that integrate with a database containing ROADrecon data. The database model in ROADlib is automatically generated based on the metadata definition of the Azure AD internal API. ROADlib lives in the ROADtools namespace, so to import it in your scripts use `from roadtools.roadlib import X`

## ROADrecon
![PyPI version](https://img.shields.io/pypi/v/roadrecon.svg)
[![Build Status](https://dev.azure.com/dirkjanm/ROADtools/_apis/build/status/dirkjanm.ROADtools?branchName=master)](https://dev.azure.com/dirkjanm/ROADtools/_build/latest?definitionId=19&branchName=master)

ROADrecon is a tool for exploring information in Azure AD from both a Red Team and Blue Team perspective. In short, this is what it does:
* Uses an automatically generated metadata model to create an SQLAlchemy backed database on disk.
* Use asynchronous HTTP calls in Python to dump all available information in the Azure AD graph to this database.
* Provide plugins to query this database and output it to a useful format.
* Provide an extensive interface built in Angular that queries the offline database directly for its analysis.

ROADrecon uses `async` Python features and is only compatible with Python 3.6-3.8 (development is done with Python 3.8). 

### Installation
There are multiple ways to install ROADrecon:

**Using a published version on PyPi**
Stable versions can be installed with `pip install roadrecon`. This will automatically add the `roadrecon` command to your PATH.

**Using a version from GitHub**
Every commit to master is automatically built into a release version with Azure Pipelines. This ensures that you can install the latest version of the GUI without having to install `npm` and all it's dependencies. Simply download the `roadlib` and `roadrecon` zip files from the Azure Pipelines artifacts, then unzip both and install them in the correct order (`roadlib` first):

```
pip install roadlib/
pip install roadrecon/
```

You can also install them in development mode with `pip install -e roadlib/`.

**Developing the front-end**
If you want to make changes to the Angular front-end, you will need to have `node` and `npm` installed. Then install the components from git:
```
git clone https://github.com/dirkjanm/roadtools.git
pip install -e roadlib/
pip install -e roadrecon/
cd roadrecon/frontend/
npm install
```

You can run the Angular frontend with `npm start` or `ng serve` using the Angular CLI from the `roadrecon/frontend/` directory. To build the JavaScript files into ROADrecon's `dist_gui` directory, run `npm build`.

### Developing
See [this README](roadrecon/README.md) for more info.
