#################################################################
#AUTHOR          : Sairaja Challagulla
#REGIONS         : ALL REGIONS
#EMAIL           : Challagulla_Sairaja@cat.com
#################################################################
import boto3
from datetime import datetime
from dateutil import tz
from boto3.dynamodb.conditions import Key, Attr

#dynamodb_resource = boto3.resource('dynamodb', region_name = 'us-east-1')

account_id = boto3.client("sts").get_caller_identity()["Account"]

client = boto3.client('sts')
sts_response = client.assume_role(RoleArn='arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB',
                                      RoleSessionName='AssumeMyRole', DurationSeconds=900)

dynamodb_resource = boto3.resource(service_name='dynamodb', region_name='us-east-1',
                              aws_access_key_id = sts_response['Credentials']['AccessKeyId'],
                              aws_secret_access_key = sts_response['Credentials']['SecretAccessKey'],
                              aws_session_token = sts_response['Credentials']['SessionToken'])

#print("dynamodb_resource",dynamodb_resource)
sm_table = dynamodb_resource.Table('secretsmanagerinventory')
#print("sm_table",sm_table)



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


def lambda_handler(event, context):
    print("Checking SM for all regions...")

    ec2_region = boto3.client('ec2').describe_regions()['Regions']
    #print("ec2_region", ec2_region)

    for region in ec2_region:
        regionName = region['RegionName']

        # SecretsMangager service is not available for Paris(eu-west-3) region so skipping for this region
        if(regionName=='eu-west-3'):
            print('Skipping for '+regionName+' region!')
            continue

        sm_client = boto3.client('secretsmanager', region_name=regionName)
        print("SM Inventory started for "+regionName+" region!")

        sm_response = sm_client.list_secrets()

        all_secrets = sm_response['SecretList']
        #print("all_secrets in "+regionName, all_secrets)

        if(len(all_secrets)<1):
            print('No Secrets found in '+regionName+' region!')
            continue

        for secret in all_secrets:
            arn = secret['ARN']
            SecretId = secret['Name']

            description = '-'
            if 'Description' in secret:
                description = secret['Description']

            lastChangedDate = timeconverter(secret['LastChangedDate']) + ' CST'

            lastRotatedDate = '-'
            if 'LastRotatedDate' in secret:
                lastRotatedDate = timeconverter(secret['LastRotatedDate']) + ' CST'

            lastAccessedDate = '-'
            if 'LastAccessedDate' in secret:
                lastAccessedDate = timeconverter(secret['LastAccessedDate']) + ' CST'

            deletedDate = '-'
            if 'DeletedDate' in secret:
                deletedDate = timeconverter(secret['DeletedDate']) + ' CST'

            kmsKeyId = '-'
            if 'KmsKeyId' in secret:
                kmsKeyId = secret['KmsKeyId']

            rotationEnabled = '-'
            if 'RotationEnabled' in secret:
                rotationEnabled = secret['RotationEnabled'] # boolean

            rotationLambdaARN = '-'
            if 'RotationLambdaARN' in secret:
                rotationLambdaARN = secret['RotationLambdaARN']

            rotationRules = '-'
            if 'rotationRules' in secret:
                rotationRules = secret['rotationRules'] # object

            secretVersionsToStages = secret['SecretVersionsToStages'] # object

            tags = '-'
            if 'Tags' in secret:
                tags = secret['Tags'] # array of objects


            print("arn: "+arn+", SecretId: "+SecretId+", description: "+description+", lastRotatedDate: "+lastRotatedDate+", lastChangedDate: "+lastChangedDate+", lastAccessedDate: "+lastAccessedDate+", deletedDate: "+deletedDate+", kmsKeyId: "+kmsKeyId+", rotationEnabled: "+str(rotationEnabled)+", rotationLambdaARN: "+rotationLambdaARN+", rotationRules: "+str(rotationRules)+", secretVersionsToStages: "+str(secretVersionsToStages)+", tags: "+str(tags))

            print("Inserting SM inventory data into DynamoDB table")
            sm_table.put_item ( #inserting items into table
                    Item={
                            'SecretId' : SecretId, #primary key
                            'SecretCount' : account_id + ' - ' +  regionName + ' - ' + lastChangedDate, #sort key
                            'Arn' : arn,
                            'Description' : description,
                            'LastRotatedDate': lastRotatedDate,
                            'LastChangedDate' : lastChangedDate,
                            'LastAccessedDate' : lastAccessedDate,
                            'DeletedDate': deletedDate,
                            'KmsKeyId' : kmsKeyId,
                            'RotationEnabled' : rotationEnabled,
                            'DeletionTime' : 'NA',
                            'RotationLambdaARN' : rotationLambdaARN,
                            'RotationRules' : str(rotationRules),
                            'SecretVersionsToStages' : str(secretVersionsToStages),
                            'Tags' : str(tags),
                            'RegionName' : regionName
                        }
                    )

        print('SM Inventory completed for '+regionName+' region')

    print('SM Inventory completed for all regions!')
