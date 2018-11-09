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
athena_table = dynamodb_resource.Table('athenainventory')




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
    print("Checking Athena for all regions...")

    # Athena service is not available for all regions, it is available for below 11 regions only (as of now)
    athena_region = ['us-east-1', 'us-east-2', 'us-west-2', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'eu-central-1', 'eu-west-1', 'eu-west-2']
    #print("athena_region", athena_region)

    for regionName in athena_region:

        athena_client = boto3.client('athena', region_name=regionName)
        print("Athena Inventory started for "+regionName+" region!")

        athena_list = athena_client.list_named_queries()

        all_athena_queries_ids = athena_list['NamedQueryIds']
        #print("all_athena_queries_ids in "+regionName, all_athena_queries_ids)

        if(len(all_athena_queries_ids)<1):
            print('No Athena found in '+regionName+' region!')
            continue

        all_athena_queries = athena_client.batch_get_named_query(NamedQueryIds=all_athena_queries_ids)
        print("all_athena_queries", all_athena_queries)

        named_queries = all_athena_queries['NamedQueries']
        unprocessed_named_query_ids = all_athena_queries['UnprocessedNamedQueryIds']

        for named_query in named_queries:
            namedQueryId = named_query['NamedQueryId']   # primary key
            name = named_query['Name']
            database = named_query['Database']
            queryString = named_query['QueryString']
            description = '-'
            if 'Description' in named_query:
                description = named_query['Description']
                if(description==''):
                    description = '-'

            updateTime = timeconverter(datetime.now()) + ' CST'
            print("namedQueryId: "+namedQueryId+", name: "+name+", database: "+database+", queryString: "+queryString+", description: "+description)

            print("Inserting Thena inventory data into DynamoDB table")
            athena_table.put_item ( #inserting items into table
                    Item={
                            'namedQueryId' : namedQueryId, #primary key  
                            'AthenaCount' : account_id + ' - ' +  regionName + ' - ' + updateTime, #sortkey
                            'Name' : name,
                            'Database' : database,
                            'QueryString': queryString,
                            'Description' : description,
                            'UpdateTime' : updateTime,
                            'RegionName' : regionName
                        }
                    )


        print('Athena Inventory completed for '+regionName+' region')

    print('Athena Inventory completed for all regions!')
