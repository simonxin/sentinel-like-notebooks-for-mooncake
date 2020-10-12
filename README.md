# Usage
We can leverage Azure Sentinel notebooks to hunt for security threats.
Notebook usage can be referred in the below article: 
https://docs.microsoft.com/en-us/azure/sentinel/notebooks


# Install sample notebooks: 
Please follow the below steps to create a machine learning workspace:
1) Use the instructions at Azure Machine Learning SDK to install the Azure Machine Learning SDK for Python
2) Create an Azure Machine Learning workspace.
3) Write a configuration file file (aml_config/config.json).
4) Clone the GitHub repository.
    ```bash
        git clone https://github.com/simonxin/sampleNotebooks.git
    ````
5) Start the notebook server from your cloned directory.

    ```bash
        jupyter notebook
    ```

more information can be referred in the below article:
https://docs.azure.cn/en-us/machine-learning/samples-notebooks


# Configure msticpyconfig.yaml file from your cloned folder:
To use the notebook, you need to edit the msticpyconfig.yaml file. 
You can refer the below document: 
https://msticpy.readthedocs.io/en/latest/data_acquisition/DataProviders.html?highlight=msticpyconfig.yaml#configuration-in-msticpyconfig-yaml

```sample_file
AzureSentinel:
  Workspaces:
    # Workspace used if you don't explicitly name a workspace when creating WorkspaceConfig
    # Specifying values here overrides config.json settings unless you explictly load
    # WorkspaceConfig with config_file parameter (WorkspaceConfig(config_file="../config.json")
    Default:
      WorkspaceId: "<your_log_analytic_workspace_ID>"
      TenantId: "<your_AAD_tenant_ID>"
QueryDefinitions:
  # Add paths to folders containing custom query definitions here
  Custom:
TIProviders:
  # If a provider has Primary: True it will be run by default on IoC lookups
  # Secondary providers can be
  OTX:
    Args:
      AuthKey: "<your_registered_OTX_key>"
    Primary: True
    Provider: "OTX" # WARNING - Do not change Provider values!
  VirusTotal:
    Args:
      AuthKey: "<your_registered_Virustotal_key>"
    Primary: False
    Provider: "VirusTotal"
  XForce:
    # You can store items in an environment variable using this syntax
    Args:
      ApiID: "<your_registed_xforce_ID>"
      AuthKey: "<your_registered_xforce_key>"
    Primary: True
    Provider: "XForce"
OtherProviders:
  GeoIPLite:
    Args:
      AuthKey: "<your_registered_GeoIPList_key>"
      DBFolder: "~/.msticpy"
    Provider: "GeoLiteLookup"
DataProviders:
  AzureCLI:
    Args:
      clientId: "<client_ID>"
      tenantId: "<your_AAD_Tenant_ID>"
      clientSecret: "<client_Secret>"
```

Note：
We can use the below four public Threat intelligence providers to do threat hunting. To use the Threat intelligence provider API, you may need to register on each provider and get the access key.
For more informtion, please check the below document:  
https://techcommunity.microsoft.com/t5/azure-sentinel/using-threat-intelligence-in-your-jupyter-notebooks/ba-p/860239

You may need to go to the target Threat intelligence provider web to register and request API auth keys: 

## virustotal: 
https://developers.virustotal.com/v3.0/reference#overview

## OTX

## VirusTotal 
https://developers.virustotal.com/reference

## AlienVault Open Threat Exchange 
https://otx.alienvault.com/api

## IBM XForce 
https://api.xforce.ibmcloud.com/doc/

## GeoIPLite
https://dev.maxmind.com/geoip/geoip2/geolite2/



# Configure workspace in file config.json in your cloned folder:  
To connect your log analytics workspace into notebook, edit the config.json file under the cloned folder: 
```config.json
{
    "tenant_id": "<your_AAD_tenant_ID>",
    "subscription_id": "<your_subscription_ID>",
    "resource_group": "<Resource_group_of_your_log_analytics_workspace>",
    "workspace_id": "<your_workspace_ID>",
    "workspace_name": "<your_workspace_name>"
}
```
