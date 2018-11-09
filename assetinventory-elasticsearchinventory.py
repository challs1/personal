##################################################################
#AUTHOR          : Sairaja Challagulla
#REGIONS         : ALL REGIONS
#EMAIL           : Challagulla_Sairaja@cat.com
##################################################################
import boto3
from datetime import datetime
from dateutil import tz
from boto3.dynamodb.conditions import Key, Attr

account_id = boto3.client("sts").get_caller_identity()["Account"]

#dynamodb_resource = boto3.resource('dynamodb', region_name = 'us-east-1')

#comment line 8 and uncomment line from 12 to 19

client = boto3.client('sts')
sts_response = client.assume_role(RoleArn='arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB',
                                      RoleSessionName='AssumeMyRole', DurationSeconds=900)

dynamodb_resource = boto3.resource(service_name='dynamodb', region_name='us-east-1',
                              aws_access_key_id = sts_response['Credentials']['AccessKeyId'],
                              aws_secret_access_key = sts_response['Credentials']['SecretAccessKey'],
                              aws_session_token = sts_response['Credentials']['SessionToken'])

#print("dynamodb_resource",dynamodb_resource)
elastic_table = dynamodb_resource.Table('elasticsearchinventory')
#print("elastic_table",elastic_table)

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
    print("Checking ElasticSearch for all regions...")

    ec2_region = boto3.client('ec2').describe_regions()['Regions']
    #print("ec2_region", ec2_region)

    for region in ec2_region:
        regionName = region['RegionName']

        #if(regionName!='us-east-2'):
        #    continue

        es_client = boto3.client('es', region_name=regionName)
        print("ElasticSearch Inventory started for "+regionName+" region!")

        es_response = es_client.list_domain_names()

        all_domains = es_response['DomainNames']
        #print("all_domains in "+regionName, all_domains)

        if(len(all_domains)<1):
            print('No ElasticSearch domains found in '+regionName+' region!')
            continue

        domain_names = []

        for domain in all_domains:
            domain_names.append(domain['DomainName'])

        all_domains_details = es_client.describe_elasticsearch_domains(DomainNames=domain_names)

        print("all_domains_details ", all_domains_details)

        for domain_details in all_domains_details['DomainStatusList']:

            domainName = domain_details['DomainName']
            domainId = domain_details['DomainId']
            arn = domain_details['ARN']
            created = domain_details['Created']
            deleted = domain_details['Deleted']

            endpoint = '-'
            if 'Endpoint' in domain_details:
                endpoint = domain_details['Endpoint']

            elasticsearchVersion = domain_details['ElasticsearchVersion']
            #endpoints = domain_details['Endpoints']

            processing = domain_details['Processing']
            accessPolicies = domain_details['AccessPolicies']
            ebsOptions = domain_details['EBSOptions']
            elasticsearchClusterConfig = domain_details['ElasticsearchClusterConfig']
            snapshotOptions = domain_details['SnapshotOptions']

            vpcOptions = '-'
            if 'VPCOptions' in domain_details:
                vpcOptions = domain_details['VPCOptions']

            cognitoOptions = domain_details['CognitoOptions']
            encryptionAtRestOptions = domain_details['EncryptionAtRestOptions']

            nodeToNodeEncryptionOptions = '-'
            if 'NodeToNodeEncryptionOptions' in domain_details:
                nodeToNodeEncryptionOptions = domain_details['NodeToNodeEncryptionOptions']

            advancedOptions = domain_details['AdvancedOptions']

            logPublishingOptions = '-'
            if 'LogPublishingOptions' in domain_details:
                logPublishingOptions = domain_details['LogPublishingOptions']


            domain_config_details = es_client.describe_elasticsearch_domain_config(DomainName=domainName)
            es_config = domain_config_details['DomainConfig']['ElasticsearchVersion']['Status']

            creationDate = timeconverter(es_config['CreationDate']) + ' CST'
            updateDate = timeconverter(es_config['UpdateDate']) + ' CST'
            updateVersion = es_config['UpdateVersion']
            state = es_config['State']
            pendingDeletion = es_config['PendingDeletion']

            print("arn: "+arn+", domainName: "+domainName+", domainId: "+domainId+", endpoint: "+endpoint+", RegionName: "+regionName)

            print("Inserting ElasticSearch inventory data into DynamoDB table")
            elastic_table.put_item ( #inserting items into table
                    Item={
                            'DomainName' : domainName, #primary key
                            'ESCount': account_id+' - '+regionName+' - '+creationDate,
                            'AccountId': account_id,
                            'DomainId' : domainId,
                            'Arn' : arn,
                            'Endpoint': endpoint,
                            'CreationDate': creationDate,
                            'UpdateDate': updateDate,
                            'UpdateVersion': updateVersion,
                            'State': state,
                            'PendingDeletion': pendingDeletion,
                            'Created': created,
                            'Deleted': deleted,
                            'ElasticsearchVersion': elasticsearchVersion,
                            #'Endpoints': str(endpoints),
                            'Processing': processing,
                            'AccessPolicies': accessPolicies,
                            'EBSOptions': str(ebsOptions),
                            'ElasticsearchClusterConfig': str(elasticsearchClusterConfig),
                            'AccessPolicies': accessPolicies,
                            'SnapshotOptions': str(snapshotOptions),
                            'VPCOptions': str(vpcOptions),
                            'CognitoOptions': str(cognitoOptions),
                            'EncryptionAtRestOptions': str(encryptionAtRestOptions),
                            'NodeToNodeEncryptionOptions': str(nodeToNodeEncryptionOptions),
                            'AdvancedOptions': str(advancedOptions),
                            'LogPublishingOptions': str(logPublishingOptions),
                            'RegionName' : regionName
                        }
                    )

        print('ElasticSearch Inventory completed for '+regionName+' region')

    print('ElasticSearch Inventory completed for all regions!')
