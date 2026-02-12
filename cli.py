#this cli file is used to run the application from the command line and define the whole contract of the application

#this file will contain the logic to run the application from the command line and it will also contain the logic to parse the command line arguments and run the appropriate functions based on the command line arguments passed by the user.

import typer #for command line interface
from aws.adapter import run_aws_scan #for running the aws scan

#create a typer app instance
app = typer.Typer(help="Nirikshak - Cloud Security Misconfiguration Scanner")

scan_app = typer.Typer(help="Scan cloud providers for misconfigurations")

@scan_app.command() #this command will run the aws scan
def aws(
    region: str = typer.Option(..., help="AWS region"),
    profile: str = typer.Option(None, help="AWS profile"),
):
    #this function will run the aws scan based on the provider argument and in the future we will add for other cloud providers as well like azure and gcp

        run_aws_scan(profile, region)


# add the scan sub-app to the main app
app.add_typer(scan_app, name="scan")

if __name__ == "__main__":
    app()