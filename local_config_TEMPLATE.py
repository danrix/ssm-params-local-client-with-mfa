# Config file

local = {
    "ssm_aws_profile": "", # e.g., for Nelson Mandela: 'nm'
    "mfa_suffix": "" # e.g., 'mfa_virt_nm'
}

ssm = {
    "default_region": "", # e.g., 'us-west-1'
    "params_basepath": "example", # add origin and ending slashes programmatically
    # all params will use base path. After base path, use 'branches' to grant users access
    # to specific segments of secrets
    "account_number": 112233 # number: AWS account number (AWS does not consider this a secret)
}