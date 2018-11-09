#################################################################
#AUTHOR          : Sairaja Challagulla
#DESCRIPTION     : THIS FUNCTION GETS IAM INVENTORY AND PUTS IN DYNAMODB TABLE.
#REGIONS         : US REGIONS
#EMAIL           : Challagulla_Sairaja@cat.com
#################################################################

import boto3
import traceback
from datetime import datetime
from dateutil import tz
import itertools
from boto3.dynamodb.conditions import Attr

def lambda_handler(event, context) :
    try :
        ################################################
        
                        #IAM INVENTORY
        
        ###############################################
        def iaminventory() :
            try :     
                iam_username = ''
                iamuserlist = []
                iam_user_list = []
                accesskeyscountlist = []
                ownerid1 = ''
                
                
                iam_table = dynamodb_resource.Table('iaminventory')
                iam_client = boto3.client('iam')
                iam_user_response = iam_client.list_users()
                
                for iam_user in  iam_user_response['Users']:
                    print(iam_user['UserName'])
                    
                    iam_user_list.append(iam_user['UserName'])
                    iamuserlist.append(iam_user['UserName'])
                    ownerid = iam_user['Arn'].split(':')
                    ownerid1 = ownerid[4]
                    
                    
                    iam_user_creationdate = timeconverter(iam_user['CreateDate']) + ' CST'
                    print('-------------------------------------')
                    
                    try :
                        iam_user_password = iam_client.get_login_profile(UserName=iam_user['UserName'])
                        iam_user_password_createddate = timeconverter(iam_user_password['LoginProfile']['CreateDate'])
                        iam_user_password_age = str((datetime.strptime(todaysdatetime, '%m-%d-%Y %I:%M:%S %p')-datetime.strptime(iam_user_password_createddate, '%m-%d-%Y %I:%M:%S %p')).days) + ' days'
                        iam_user_password_resetrequired = iam_user_password['LoginProfile']['PasswordResetRequired']
                        print('Password Exisits')
                    except Exception :
                        print('Password Disabled')
                        iam_user_password_createddate = 'No Console Login Enabled'
                        iam_user_password_resetrequired = 'None'
                        iam_user_password_age = 'None'
                    
                    if iam_user.get('PasswordLastUsed') :
                        iam_user_password_lastused = timeconverter(iam_user['PasswordLastUsed'])
                        iam_user_password_lastused_indays = str((datetime.strptime(todaysdatetime, '%m-%d-%Y %I:%M:%S %p')-datetime.strptime(iam_user_password_lastused, '%m-%d-%Y %I:%M:%S %p')).days) + ' days'
                        print(iam_user_password_lastused)
                    else :
                        iam_user_password_lastused_indays = 'None'
                    
                    iam_access_keys_response = iam_client.list_access_keys(UserName = iam_user['UserName'])
                    for iam_access_keys, iam_users in itertools.zip_longest(iam_access_keys_response['AccessKeyMetadata'], iam_user_list):
                            
                            if iam_user['UserName'] != iam_username :
                                accesskeycount = 1
                            else :
                                accesskeycount += 1
                            iam_username = iam_user['UserName']
                            
                            if iam_access_keys :
                                iam_access_key_id = iam_access_keys['AccessKeyId']
                                iam_access_keys_creationdate = timeconverter(iam_access_keys['CreateDate'])
                                iam_access_key_age = str((datetime.strptime(todaysdatetime, '%m-%d-%Y %I:%M:%S %p')-datetime.strptime(iam_access_keys_creationdate, '%m-%d-%Y %I:%M:%S %p')).days) + ' days'
                                iam_access_key_status = iam_access_keys['Status']
                                print('Access key exists')
                                
                                iam_access_key_last_used_response = iam_client.get_access_key_last_used(AccessKeyId=iam_access_keys['AccessKeyId'])
                                iam_access_key_last_used_dict = iam_access_key_last_used_response['AccessKeyLastUsed']
                                
                                if iam_access_key_last_used_dict.get('LastUsedDate') :
                                    iam_access_keys_last_useddate = timeconverter(iam_access_key_last_used_dict['LastUsedDate'])
                                    iam_access_keys_last_useddate_indays = str((datetime.strptime(todaysdatetime, '%m-%d-%Y %I:%M:%S %p')-datetime.strptime(iam_access_keys_last_useddate, '%m-%d-%Y %I:%M:%S %p')).days) + ' days'
                                else :
                                    iam_access_keys_last_useddate_indays = 'Never Used'
                                    print('Never Used')
                            else  :
                                print('No AccessKey')
                                iam_access_key_id = 'None'
                                iam_access_key_age = 'None'
                                iam_access_keys_last_useddate_indays = 'None'
                                iam_access_key_status = 'None'
                                iam_access_keys_creationdate = 'None'
                           
                            sortcount =  ownerid[4] + ' - ' + iam_user_creationdate + ' - ' + iam_access_keys_creationdate
                            accesskeyscountlist.append(sortcount)
                            print(sortcount)
                                
                            iam_table.put_item ( #inserting items into table
                                                            Item={
                                                                'UserName': iam_user['UserName'], #primary key
                                                                'AccessKeysCount' : sortcount,
                                                                'AAKeyCount' : str(accesskeycount),
                                                                'OwnerId' : sts_client_account,
                                                                'OwnerAlias'  : account_alias,
                                                                'AccessKeyId' :iam_access_key_id ,
                                                                'AccessKeyAge' : iam_access_key_age,
                                                                'AccessKeyLastUsedInDays' : iam_access_keys_last_useddate_indays,
                                                                'AccessKeyStatus' : iam_access_key_status,
                                                                'PasswordAge' : iam_user_password_age,
                                                                'PasswordReset' : iam_user_password_resetrequired,
                                                                'PasswordLastUsedInDays' : iam_user_password_lastused_indays,
                                                                'UserCreationDate' : iam_user_creationdate,
                                                                'LastExecutedTime' : todaysdatetime + ' CST',
                                                                'UserStatus' : 'Active'           
                                                                        }
                                                                        )
                            clearlist(iam_user_list)
                            
                    print('')
                if not iamuserlist :
                    iamuserlist.append('emptylist')
                resultsearchdeleteduser = searchdeleteduser(iamuserlist,accesskeyscountlist,iam_table,sts_client_account)
                return resultsearchdeleteduser
            except Exception :
                print(traceback.format_exc())
                return 'fail'
                
        #########################################################
        
                    #SEARCHING FOR DELETED USER                
        
        #########################################################
        def searchdeleteduser(iamuserlist,accesskeyscountlist,iam_table,ownerid) :
            try :
                iam_table_scan = iam_table.scan(FilterExpression=Attr('OwnerId').eq(ownerid) & Attr('UserStatus').ne('Deleted'))
                print(len(iam_table_scan['Items']))
                iam_table_scan_ext = iam_table_scan['Items']
                
                while iam_table_scan.get('LastEvaluatedKey'):
                    iam_table_scan = iam_table.scan(ExclusiveStartKey=iam_table_scan['LastEvaluatedKey'],FilterExpression=Attr('OwnerId').eq(ownerid) & Attr('UserStatus').ne('Deleted'))
                    print('-------extension---------')
                    print(len(iam_table_scan['Items']))
                    iam_table_scan_ext += iam_table_scan['Items']
                    print(len(iam_table_scan_ext))
                print('---------------------------------------')
                print('Looking for Deleted Users')
                for items in iam_table_scan_ext :
                    
                    if items['UserStatus'] != 'Deleted' :
                        for iamuser in iamuserlist :
                            if items['UserName'] == iamuser:
                                matid = 'matched'
                                break
                            else :
                                matid = 'not matched'
                        if matid == 'matched' :
                            for accesskeyscount in accesskeyscountlist :
                                if items['AccessKeysCount'] == accesskeyscount:
                                    matid = 'matched'
                                    break
                                else :
                                    matid = 'not matched'
                            
                        if matid == 'not matched' : #and ownerid == items['OwnerId']:
                            print("Found Deleted User")
                            print(items['UserName'])
                            print(items['AccessKeysCount'])
                            print('================================')
                            response = iam_table.update_item(
                                       Key={
                                            'UserName':items['UserName'],
                                            'AccessKeysCount' : items['AccessKeysCount']
                                        },
                                        UpdateExpression="set UserStatus= :r, DeletedTime= :d",
                                        ExpressionAttributeValues={
                                            ':r' : 'Deleted',
                                            ':d' : todaysdatetime + ' CST'
                                        },
                                        ReturnValues="UPDATED_NEW"
                            )    
                return 'success'    
            except Exception as e:
                print(traceback.format_exc())
                return 'fail'

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
        def clearlist(tlist) :
            tlist[:] = []
            
        todaysdatetime = timeconverter(datetime.now())
        
        iam_client = boto3.client('iam')
        iam_response = iam_client.list_account_aliases()
        if iam_response.get('AccountAliases') :
            account_alias = iam_response['AccountAliases'][0]
        else :
            account_alias = 'No Alias'
            
        sts_client_account = boto3.client('sts').get_caller_identity()['Account']
        
        sts_client = boto3.client('sts')
        assumedRoleObject = sts_client.assume_role(
        RoleArn="arn:aws:iam::620890749476:role/Assetsinventory_Trusted_DynamoDB",
        RoleSessionName="assumerole2"
        )
        credentials = assumedRoleObject['Credentials']
        dynamodb_resource = boto3.resource('dynamodb', region_name = 'us-east-1', aws_access_key_id = credentials['AccessKeyId'], aws_secret_access_key = credentials['SecretAccessKey'], aws_session_token = credentials['SessionToken'])
        
        result = iaminventory()
        return result       
    except Exception :
        print('error occured')
        print(traceback.format_exc())
        return 'failed'
        
    
    