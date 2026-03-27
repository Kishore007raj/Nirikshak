import logging
import sys

def setup_logging(verbose: bool = False, quiet: bool = False):
    """
    Configures logging for Nirikshak.
    - Suppresses Azure SDK noise.
    - Sets default level to INFO or DEBUG if verbose.
    - If quiet, only critical errors are shown via logger.
    """
    
    # Hide Azure SDK noise
    azure_logger = logging.getLogger("azure")
    azure_logger.setLevel(logging.WARNING)
    
    auth_logger = logging.getLogger("azure.identity")
    auth_logger.setLevel(logging.WARNING)
    
    http_logger = logging.getLogger("azure.core.pipeline.policies.http_logging_policy")
    http_logger.setLevel(logging.WARNING)

    # Set base level
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.INFO

    # Configure root logger
    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=sys.stdout,
        force=True
    )
