# roadoidc
Utilities to set up a minimal OpenID Connect (OIDC) Provider. Provides a Flask app for usage with Azure App Service to host your own IdP to abuse federated credentials. Background can be found on the [release blog](https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/).

# Installation
roadoidc does not come with a separate install-able tool. Rather, the code is provided as a collection of scripts. To install, clone the repository first, then install `roadlib` and `roadtx` from there to ensure you have the latest versions. You can also instead install the `requirements.txt` from the `roadoidc` directory.

```
git clone https://github.com/dirkjanm/ROADtools
cd ROADtools/
pip install roadlib/
pip install roadtx/
cd roadoidc
```

# Using the tool
## Generating the configuration
The tool needs to have a certificate and private key, which will be used to sign tokens later. We can generate these and a config with the `genconfig.py` script.

```
usage: genconfig.py [-h] [--cert-pem file] [--key-pem file] -i ISSUER [-c CONFIGFILE] [-k KID]

ROADoidc - minimal OpenID Connect config generator

optional arguments:
  -h, --help            show this help message and exit
  --cert-pem file       Certificate file to store IdP cert (default: roadoidc.pem)
  --key-pem file        Private key file to store IdP key (default: roadoidc.key)
  -i ISSUER, --issuer ISSUER
                        Issuer of the federated credential - needs to be the base URL where the config is hosted
  -c CONFIGFILE, --configfile CONFIGFILE
                        File to store the configuration (default: flaskapp/app_config.py)
  -k KID, --kid KID     Key ID to use (default: SHA1 thumbprint of generated certificate
```

The default will save it in `flaskapp/app_config.py`, from where flask can pick up the values. The only required parameter is the `issuer` parameter, which must be the URL where you will host the IdP. For Azure App Services, this will be `https://yourappname.azurewebsites.net` (without trailing `/`), for Azure Blob storage, this will be `https://storagename.blob.core.windows.net/containername`. Note that these names must be globally unique, so it is best to verify the availability of these names before generating the configuration.

## Hosting as Azure App Service
After generating the configuration, the app can be hosted on Azure App Services using the Azure CLI:

```
cd flaskapp/
az webapp up -n yourappname --sku B1 --runtime PYTHON:3.10
```

After the app is up, validate that you can reach the `.well-known/openid-configuration` endpoint on your host.

## Hosting on Azure Blob Storage
After generating the configuration, we can run the flask app to generate static config files:

```
cd flaskapp/
flask run
```

In a second terminal, download the `.well-known/openid-configuration` file and the `keys` file.

```
wget http://127.0.0.1:5000/.well-known/openid-configuration -O config.json
wget http://127.0.0.1:5000/keys.json -O keys.json
```

We can now upload these files to Blob Storage with the Azure CLI (instructions adapted from [here](https://azure.github.io/azure-workload-identity/docs/installation/self-managed-clusters/oidc-issuer/discovery-document.html)).

```bash
export RESOURCE_GROUP="roadoidc"
# Change location to where you want
export LOCATION="westus2"
az group create --name "${RESOURCE_GROUP}" --location "${LOCATION}"

export AZURE_STORAGE_ACCOUNT="yourstoragename"
export AZURE_STORAGE_CONTAINER="containername"
az storage account create --resource-group "${RESOURCE_GROUP}" --name "${AZURE_STORAGE_ACCOUNT}" --allow-blob-public-access true
az storage container create --name "${AZURE_STORAGE_CONTAINER}" --public-access blob
az storage blob upload \
  --container-name "${AZURE_STORAGE_CONTAINER}" \
  --file config.json \
  --name .well-known/openid-configuration
az storage blob upload \
  --container-name "${AZURE_STORAGE_CONTAINER}" \
  --file keys.json \
  --name keys.json
```

## Hosting on other platforms
Follow the instructions above, then upload the files to the correct folders on your hosting platform of choice. Make sure the issuer URL matches with the place you upload the files.

# Requesting tokens
Info on configuring federated credentials on apps and user managed identities, and how to request tokens with roadtx can be found on the roadoidc [release blog](https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/).

## Using roadoidc as an External Authentication Method
You can also use roadoidc as an External Authentication Method (EAM) in Entra ID that fakes Multi Factor Authentication (MFA) as an EAM provider. roadoidc will approve any incoming MFA request without prompt, which means this isn't something you should be using in production environments. But, if you don't want to bother with real MFA for lab environments, you can make your life easier with roadoidc. This setup requires that roadoidc is running as an Azure App service, since this is not a static configuration. You have to specify `--eam` during the configuration generation with `genconfig.py` (see above) to ensure that this is enabled.

In Entra ID, this is set up as follows (you will need Global Admin rights to configure this):

* Create an application (app registration in Entra ID)
* Configure the roadoidc EAM URL as a redirect URL on this application. This URL consists of the `issuer` URL plus the `eam/authorize` suffix. For example, if you host roadoidc on `https://yourappname.azurewebsites.net`, the redirect URL would be `https://yourappname.azurewebsites.net/eam/authorize`
* Make sure the following permissions are configured on your app and consented by an admin: `openid`, `profile`
* Note down the client ID (app ID) of this app

* In Entra ID, go to Security -> Authentication methods -> Policies -> Add external method
* Fill in an appropriate name for the method. The name doesn't matter but will be shown to users signing in, and cannot be changed afterwards.
* The client ID can be anything since this is not checked by roadoidc. A random GUID will work.
* The discovery endpoint should be the `issuer` URL, plus the `eam/.well-known/openid-configuration` suffix. For example, if you host roadoidc on `https://yourappname.azurewebsites.net`, the discovery endpoint would be `https://yourappname.azurewebsites.net/eam/.well-known/openid-configuration`
* The App ID should be the ID of the application we created above.
* Scope the EAM to the users (or all users) you want to bypass the MFA requirement for. Again, don't use this for real/production environments, especially with a broad scope.
