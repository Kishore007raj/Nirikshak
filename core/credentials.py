"""
Credential Guard logic for NIRIKSHAK.
Provides deterministic validation of cloud credentials.
"""

import logging
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from azure.identity import DefaultAzureCredential
import google.auth
from google.auth.exceptions import DefaultCredentialsError

logger = logging.getLogger(__name__)

def is_azure_valid() -> bool:
    """Validate Azure credentials using DefaultAzureCredential token check."""
    try:
        credential = DefaultAzureCredential()
        # Fast-fail check: request management token
        credential.get_token("https://management.azure.com/.default")
        return True
    except Exception as e:
        logger.warning(f"Azure credentials invalid: {e}")
        return False

def is_aws_valid() -> bool:
    """Validate AWS credentials using STS identity check."""
    try:
        sts = boto3.client('sts')
        sts.get_caller_identity()
        return True
    except (NoCredentialsError, ClientError) as e:
        logger.warning(f"AWS credentials invalid: {e}")
        return False

def is_gcp_valid() -> bool:
    """Validate GCP credentials using google-auth default check."""
    try:
        credentials, project = google.auth.default()
        # Credentials object existing is usually enough, but we can try to refresh
        if not credentials:
            return False
        return True
    except DefaultCredentialsError as e:
        logger.warning(f"GCP credentials invalid: {e}")
        return False
