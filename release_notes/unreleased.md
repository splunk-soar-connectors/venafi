**Unreleased**
* Fixed 'create certificate' action to take default 'False' value for boolean parameter when running action via playbook [PAPP-30849]
* Added encryption for the sensitive values stored in the state file
* Removed requests and certifi dependencies in order to use platform packages [PAPP-30822, PAPP-31906]
