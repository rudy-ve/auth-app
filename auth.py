from flask import  Blueprint ,request
from uuid import uuid4;
##from python_arptable import get_arp_table
import netifaces as nif
import datetime
import sys
sys.path.insert(1,'../authConfig')
from clsPgDatabase import pgDatabase;
from setup import getSetup;

bp=Blueprint('auth',__name__,url_prefix='/auth')

dbSetup=getSetup('authDb')
db=pgDatabase(dbSetup['host'],dbSetup['port'],dbSetup['database'],dbSetup['schema'],dbSetup['user'],dbSetup['password']);
     

def getPostData(request):
    data = None;
    if ('data' in request.form): 
        data = request.form['data]']
    elif ('data' in request.get_json()):
        data = request.get_json()['data']
    return data

def mac_from_ip(ip):
    'Returns a list of MACs for interfaces that have given IP, returns None if not found'
    for i in nif.interfaces():
        addrs = nif.ifaddresses(i)
        try:
            if_mac = addrs[nif.AF_LINK][0]['addr']
            if_ip = addrs[nif.AF_INET][0]['addr']
        except IndexError: #ignore ifaces that dont have MAC or IP
            if_mac = if_ip = None
        except  KeyError: #ignore ifaces that dont have MAC or IP
            if_mac = if_ip = None  
        if if_ip == ip:
            return if_mac
    return 'None'

def __cleanAuthorisation(userId):
    minutesToKeepAuthorisation=getSetup('minutesToKeepAuthorisation')
    parameters = [userId,minutesToKeepAuthorisation  ]
    sql = " delete from auth_token "
    sql += " where auth_authorisation_id in ( "
    sql += "      select auth_authorisation_id from auth_authorisation where auth_user_id = %s and auth_authorisation_valid_until < now() -  interval '%s minutes' "
    sql += " ) "
    db.execute(sql, parameters)

    sql = "  delete from auth_authorisation where auth_user_id = %s and auth_authorisation_valid_until < now() -  interval '%s minutes' "
    db.execute(sql, parameters)

def __toUtc(date):
    return date.astimezone(datetime.timezone.utc)

def __getToken(authorisationId):
    minutesToKeepTokens=getSetup('minutesToKeepTokens')
    sql = " delete from auth_token where auth_token_valid_until < now() -  interval '%s minutes' "
    db.execute ( sql , [minutesToKeepTokens] )
    
    sql = " select auth_token ,  auth_token_valid_until  from auth_token  where  auth_authorisation_id = %s and auth_token_valid_until > now() +  interval '2 minutes' "
    sql += " order by auth_token_valid_until desc "
    parameters = [authorisationId]
    row = db.fetchOne(sql,parameters)

    if (row is not None):
        validUntil= __toUtc(row['auth_token_valid_until'])
        return {'token':row['auth_token'], 'validUntil':validUntil }
    else:
        token = uuid4();
        parameters = [authorisationId , str(token) , getSetup('tokenValidMinutes') ]
        sql =   'insert into auth_token  ( auth_authorisation_id, auth_token, auth_token_valid_until ) '
        sql +=  " values (%s,%s,now() + interval '%s minutes')"
        sql +=  " returning   auth_token_valid_until"
        row=db.fetchOne(sql,parameters)
        db.commit()

        validUntil= __toUtc(row['auth_token_valid_until'])

        return  {'token': token, 'validUntil': validUntil }


@bp.route('alive',methods=['GET'])
def alive():
    return "Alive and kicking"


@bp.route('authenticate',methods=['GET'])
def authenticate():

    ip = request.remote_addr ;
    user = request.args.get('user')
    pwd = request.args.get('pwd')
    mac = mac_from_ip(ip)


    sql = " select auth_user_id from auth_user where auth_user_name = %s and auth_user_password = crypt(%s,auth_user_password) "
    parameters = [user,pwd]
    row = db.fetchOne(sql,parameters) 
    if ( row is None ) :
        return {'authenticated':False,'Error': 'Gebruiker en/of paswoord zijn niet correct'}
    
    userId = row['auth_user_id']
    sql  = " select auth_authorisation_id , timezone('utc',auth_authorisation_valid_until) as  auth_authorisation_valid_until  from auth_authorisation "
    sql += " where auth_user_id = %s and auth_ip = %s and auth_mac = %s and auth_authorisation_valid_until >= now() +  interval '2 minutes' " 
    sql += "   order by auth_authorisation_valid_until desc "
    parameters = [userId, ip ,mac ]
    row = db.fetchOne(sql,parameters)

    authorisationId = None
    authValidUntil = None
    if ( row is not None) :
        authorisationId = row['auth_authorisation_id']
        authValidUntil = __toUtc(row['auth_authorisation_valid_until'])
    else:
        
        sql = ' insert into auth_authorisation (auth_user_id, auth_mac, auth_ip , auth_authorisation_valid_until)  '
        sql += " values (%s,%s,%s,now() + interval '%s minutes')"
        sql += " returning auth_authorisation_id ,  auth_authorisation_valid_until"
        parameters = [userId , mac , ip , getSetup('authValidMinutes')   ]
        row = db.fetchOne(sql,parameters)
        db.commit()
        authValidUntil = __toUtc(row['auth_authorisation_valid_until'])
        authorisationId = row['auth_authorisation_id']

    token = __getToken(authorisationId)
    __cleanAuthorisation(userId)
    db.commit();
    return {'authenticated':True,'authValidUntil': authValidUntil ,'token':token['token'] , 'tokenValidUntil' : token['validUntil']}

@bp.route('refreshToken',methods=['GET'])
def refreshToken():
    user =  request.args.get('user') 
    oldToken = request.args.get('token') 
    ip   = request.remote_addr ;
    mac = mac_from_ip(ip)

    sql  = " select aa.auth_authorisation_id, au.auth_user_id   from auth_user au "
    sql += "     inner join auth_authorisation aa on  aa.auth_user_id = au.auth_user_id " 
    sql += "     inner join auth_token at on at.auth_authorisation_id = aa.auth_authorisation_id " 
    sql += "   where au.auth_user_name = %s  and aa.auth_ip = %s and aa.auth_mac = %s "
    sql += "      and at.auth_token = %s "
    sql += "     and aa.auth_authorisation_valid_until >= now() and at.auth_token_valid_until >= now() "
    
    row = db.fetchOne(sql,[user,ip,mac, oldToken])
    if ( row is None):
        return {'authenticated':False , 'error': 'Refresh token failed'}
    
    authorisationId = row['auth_authorisation_id']
    userId = row['auth_user_id']

    token = __getToken(authorisationId)
    __cleanAuthorisation(userId)
    db.commit();
    return {'authenticated':True,'token':token['token'] , 'tokenValidUntil' : token['validUntil']}

@bp.route('refreshAuthentication',methods=['GET'])
def refreshAuthentication():
    
    ip = request.remote_addr ;
    user = request.args.get('user')
    token = request.args.get('token')
    authStatus = __isAuthenticated(user,token,ip)
    
    if ( not( authStatus['authenticated'])) :
        return {'authenticated':False,'Error': 'Authentication refresh failed'}

    sql = " update auth_authorisation set auth_authorisation_valid_until = now() + interval '%s minutes' " 
    sql += " where auth_authorisation_id = %s  "
    sql += " returning  auth_authorisation_valid_until"
    parameters = [ getSetup('authValidMinutes') , authStatus['authorisationId']  ]
    row = db.fetchOne(sql,parameters)
    db.commit()
    authValidUntil = __toUtc(row['auth_authorisation_valid_until'])

    db.commit();
    return {'authenticated':True,'authValidUntil': authValidUntil }

def __isAuthenticated(user,token,ip):
    mac = mac_from_ip(ip)
    sql  = " select aa.auth_authorisation_id , au.auth_user_id from auth_user au "
    sql += "     inner join auth_authorisation aa on  aa.auth_user_id = au.auth_user_id " 
    sql += "     inner join auth_token at on at.auth_authorisation_id = aa.auth_authorisation_id " 
    sql += "   where au.auth_user_name = %s  and aa.auth_ip = %s and aa.auth_mac = %s "
    sql += "      and at.auth_token = %s "
    sql += "     and aa.auth_authorisation_valid_until >= now() and at.auth_token_valid_until >= now() "
    row = db.fetchOne(sql,[user,ip,mac, token])
    db.rollback();
    if ( row is not None ):
        return {'authenticated':True , 'authorisationId': row['auth_authorisation_id'] } 
    else:
        return {'authenticated':False  } 

@bp.route('isAuthenticated',methods=['GET'])
def isAuthenticated():
    user =  request.args.get('User') 
    token = request.args.get('Token') 
    ip   =  request.args.get('Ip') 
    authStatus=__isAuthenticated(user,token,ip);

    return {'authenticated':authStatus['authenticated']} 


@bp.route('getToken',methods=['GET'])
def getToken():
    user =  request.args.get('user') 
    ip   =  request.remote_addr ;
    mac = mac_from_ip(ip)
    sql  = " select aa.auth_authorisation_id from auth_user au "
    sql += "     inner join auth_authorisation aa on aa.auth_user_id = au.auth_user_id " 
    sql += "   where au.auth_user_name = %s and aa.auth_authorisation_valid_until > now() and aa.auth_ip = %s and aa.auth_mac = %s "
    row = db.fetchOne(sql,[user,ip,mac])
    if (  row is None ):
        return {'authenticated':False,'token':'' , 'tokenValidUntil' : ''}
    token = getToken(row['auth_authorisation_id'])
    return { 'authenticated':True,'token':token['token'] , 'tokenValidUntil' : token['validUntil']}

@bp.route('logout',methods=['POST'])
def logout():
    data = getPostData(request);
    user =  data['user'] 
    ip   =  request.remote_addr ;
    mac = mac_from_ip(ip)
    parameters = [ip , mac , user ]
    authSel= " from auth_authorisation where auth_ip = %s and auth_mac = %s and auth_user_id in (select auth_user_id from auth_user where auth_user_name = %s) "

    sql = " delete from auth_token where auth_authorisation_id in ( select auth_authorisation_id " + authSel + ")" 
    db.execute(sql,parameters);
    
    sql = " delete " + authSel
    db.execute(sql,parameters);
    db.commit()

    return { 'authenticated':False }
