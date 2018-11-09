#################################################################
#AUTHOR          : Sairaja Challagulla
#REGIONS         : ALL REGIONS
#EMAIL           : Challagulla_Sairaja@cat.com
#################################################################
import boto3
from datetime import datetime
from dateutil import tz
from boto3.dynamodb.conditions import Key, Attr

account_id = boto3.client("sts").get_caller_identity()["Account"]

# dynamodb_resource = boto3.resource('dynamodb', region_name = 'us-east-1')

client = boto3.client('sts')
sts_response = client.assume_role(RoleArn='arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB',
                                     RoleSessionName='AssumeMyRole', DurationSeconds=900)

dynamodb_resource = boto3.resource(service_name='dynamodb', region_name='us-east-1',
                             aws_access_key_id = sts_response['Credentials']['AccessKeyId'],
                             aws_secret_access_key = sts_response['Credentials']['SecretAccessKey'],
                             aws_session_token = sts_response['Credentials']['SessionToken'])

#print("dynamodb_resource",dynamodb_resource)
inspector_table = dynamodb_resource.Table('inspectorinventory')
#print("inspector_table",inspector_table)


def timeconverter(srctime) :
    totimezone = 'US/Central'
    curtime = srctime.strftime("%m-%d-%Y %I:%M:%S %p")

    from_zone = tz.tzutc()
    to_zone = tz.gettz(totimezone)
    utc = datetime.strptime(curtime, '%m-%d-%Y %I:%M:%S %p')
    utc = utc.replace(tzinfo=from_zone)
    # Convert time zone
    tocentral = utc.astimezone(to_zone).strftime("%m-%d-%Y %I:%M:%S %p")

    return tocentral


def get_available_assessment_targets_from_db(region):
    try:
        response = inspector_table.scan(
            FilterExpression=Attr('isDeleted').eq('No') & Attr('RegionName').eq(region)
        )
    except Exception as e:
        print(e.response['Error']['Message'])
        return []
    else:
        items = response['Items']
        print("GetItems succeeded:", items)
        return items

def get_deleted_assessment_targets(assessment_targets, all_assessment_targets_from_db):
    all_targets = []
    targets_from_db = []
    deleted_targets = []

    for target in assessment_targets:
       all_targets.append(target['name'])

    for target in all_assessment_targets_from_db:
       targets_from_db.append(target['TargetName'])

    for target in targets_from_db:
        if target not in all_targets:
            deleted_targets.append(target)

    return deleted_targets


def update_deleted_assessment_targets(deleted_assessment_targets) :
    for target in deleted_assessment_targets:
        current_time = timeconverter(datetime.now()) + ' CST'
        response = inspector_table.update_item(
            Key={
                'TargetName': target
            },
            UpdateExpression="set isDeleted = :r, DeletionTime=:p",
            ExpressionAttributeValues={
                ':r': 'Yes',
                ':p': current_time
            },
            ReturnValues="UPDATED_NEW"
        )
        print("UpdateItem succeeded NamedQueryId: "+query_id)


def lambda_handler(event, context):
    print("Checking Inspector targets for all regions...")

    # Inspector service is not available for all regions, it is available for below 10 regions only (as of now)
    inspector_region = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-2', 'eu-central-1', 'eu-west-1']
    #print("inspector_region", inspector_region)

    for regionName in inspector_region:

        #if(regionName!='us-east-2'):
        #    continue

        inspector_client = boto3.client('inspector', region_name=regionName)
        print("Inspector Inventory started for "+regionName+" region!")

        assessment_targets_list = inspector_client.list_assessment_targets()

        assessment_targets_arns = assessment_targets_list['assessmentTargetArns']
        #print("assessment_targets_arns in "+regionName, assessment_targets_arns)

        assessment_targets_res = inspector_client.describe_assessment_targets(assessmentTargetArns=assessment_targets_arns)
        assessment_targets = assessment_targets_res['assessmentTargets']

        all_assessment_targets_from_db = get_available_assessment_targets_from_db(regionName)
        deleted_assessment_targets = get_deleted_assessment_targets(assessment_targets, all_assessment_targets_from_db)

        for assessment_target in assessment_targets:
            arn = assessment_target['arn']
            name = assessment_target['name']  # primary key
            resourceGroupArn = '-'
            if 'resourceGroupArn' in assessment_target:
                resourceGroupArn = assessment_target['resourceGroupArn']
            createdAt = timeconverter(assessment_target['createdAt']) + ' CST'
            updatedAt = timeconverter(assessment_target['updatedAt']) + ' CST'

            assessment_templates_list = inspector_client.list_assessment_templates(assessmentTargetArns=[arn])
            assessment_templates_arns = assessment_templates_list['assessmentTemplateArns']
            assessment_templates_data = inspector_client.describe_assessment_templates(assessmentTemplateArns=assessment_templates_arns)
            assessment_templates = assessment_templates_data['assessmentTemplates']

            assessment_templates_names = []
            for assessment_template in assessment_templates:
                assessment_templates_names.append(assessment_template['name'])

            print("Inserting Inspector inventory data into DynamoDB table")
            inspector_table.put_item ( #inserting items into table
                    Item={
                            'TargetName' : name, #primary key
                            'InspectorCount' : account_id + ' - ' + regionName + ' - ' + createdAt, # sort key
                            'AccountId' : account_id,
                            'Arn' : arn,
                            'UpdatedAt' : updatedAt,
                            'ResourceGroupArn': resourceGroupArn,
                            'AssessmentTemplates' : str(assessment_templates),
                            'AssessmentTemplatesNames': str(assessment_templates_names),
                            'DeletionTime' : 'NA',
                            'IsDeleted' : 'No',
                            'RegionName' : regionName
                        }
                    )

        if(len(deleted_assessment_targets)>0):
            print("updating deleted targets for "+regionName+" region...")
            update_deleted_assessment_targets(deleted_assessment_targets)

        print('Inspector Inventory completed for '+regionName+' region')

    print('Inspector Inventory completed for all regions!')
