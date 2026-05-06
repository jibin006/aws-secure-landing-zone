import boto3
import json
import os

def lambda_handler(event, context):
    """
    IAM Role Vending Machine
    Creates roles with permission boundaries enforced.
    No role leaves this function without a boundary.
    """
    iam = boto3.client('iam')
    
    role_name = event.get('role_name')
    trust_policy = event.get('trust_policy')
    description = event.get('description', '')
    
    if not role_name or not trust_policy:
        return {
            'statusCode': 400,
            'body': 'role_name and trust_policy are required'
        }
    
    boundary_arn = os.environ['BOUNDARY_POLICY_ARN']
    
    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description=description,
            PermissionsBoundary=boundary_arn,
            Tags=[
                {'Key': 'CreatedBy', 'Value': 'iam-vending-machine'},
                {'Key': 'BoundaryEnforced', 'Value': 'true'}
            ]
        )
        
        role_arn = response['Role']['Arn']
        
        return {
            'statusCode': 200,
            'body': {
                'role_arn': role_arn,
                'boundary_applied': boundary_arn,
                'message': 'Role created with permission boundary enforced'
            }
        }
        
    except iam.exceptions.EntityAlreadyExistsException:
        return {
            'statusCode': 409,
            'body': f'Role {role_name} already exists'
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': str(e)
        }