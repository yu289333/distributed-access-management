# Distributed Access Management

Do you have IAM policies in both AWS and Azure? Or do you need to convert AWS IAM policies to Azure policies when migrating from AWS to Azure? Working with so many different types of access (authorization) policies has been the way of life. The goal of this project is to create a distributed access management that can be used AWS, Azure, GCP and all other cloud products just like Active Directory being used by all for identity and authentication management. Before achieving the goal, the project works on converting access policies among different systems. 

This project will serve as proof of concept for the patent pending technology - access policy neutral format "Optimized policy data structure for distributed authorization systems." Essentially, all access policy elements are hierachies (trees) of set operations. Each leaf is a condition which defines a set of permissions or denials. For the same access policy, the differences between different formats, e.g. AWS and Azure, are
- the conditions are defined in different namespaces e.g. AWS ARN vs. Azure URN
- the hierachy of set operations is morphed differently.
The patent pending technology is to morph the access policies in AWS format to the neutral format before morphing them to the Azure format.

## Directory structure
- /db directory contains sample policies from AWS, Azure and GCP as well as the Postgresql entity structure of storing policies
- /lambda contains AWS Lambda code in an attempt to load policies into the Postgresql -- it's not working
- /src contains Python code to convert/reduce policies to the neutral format. But the conditions are difficult to convert to a standard/neutral format.