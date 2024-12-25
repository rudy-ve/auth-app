import psycopg2
from psycopg2.extras import RealDictCursor
import json
#from flaskr.debug import debug,debugCR


class pgDatabase(object):
  def __init__(self,host,port,dbName,schema,user,password):
    self.host = host
    self.port = port
    self.dbName = dbName
    self.user = user
    self.schema = schema
    self.search_path = self.schema + ",public"
    self.connected = False
    self.password = password
    self.connection = None 

  def connect(self):
    if ( self.connected == False ):
      
      connStr = "dbname='" +self.dbName 
      connStr += "' port='" + self.port  
      connStr += "' user='" + self.user  
      connStr += "' host='" + self.host  
      connStr += "' password='" + self.password  
      connStr += "'"
      self.connection =  psycopg2.connect(connStr,cursor_factory=RealDictCursor)
      self.connected = True

  def getCursor(self):
    #print("self.connection.status " , self.connection.status )
    #print("STATUS_READY " , psycopg2.extensions.STATUS_READY )
    #print("STATUS_BEGIN " , psycopg2.extensions.STATUS_BEGIN )
    #print("STATUS_IN_TRANSACTION " , psycopg2.extensions.STATUS_IN_TRANSACTION )
    #print("STATUS_PREPARED " , psycopg2.extensions.STATUS_PREPARED )
    if  ( self.connection.status != psycopg2.extensions.STATUS_READY 
          and self.connection.status != psycopg2.extensions.STATUS_BEGIN):
      print (" RESET CONNECTION !!!!!")
      self.connection.reset()
    return self.connection.cursor()
  
  
  def execute(self,sql,*p):
    self.connect()
    cursor= self.getCursor()
    cursor.execute(sql,*p)
  
  def executeSelect(self,sql,*p):
    self.connect()
    cursor= self.getCursor()
    cursor.execute(sql,*p)
    rows=cursor.fetchall()
    if ( len(rows) > 0 ):
      return rows[0][0]
    else:
      return None

  def fetchAll(self,sql,*p):
    self.connect()
    cursor= self.getCursor()
    cursor.execute(sql,*p)
    rows=cursor.fetchall()
    return rows

  def executeFunction(self,sql,*p):
    self.connect()
    cursor= self.getCursor()
    cursor.execute("select " + sql, p )
    rows=cursor.fetchall()
    return rows[0][0]

  def executeFunctionJson(self,sql,*p):
    return json.dumps(self.executeFunction(sql,*p))
  
  def executeJson(self,sql,*p):
    return json.dumps(self.fetchAll(sql,*p))

  def commit(self):  
    self.connect()
    self.connection.commit()

  def rollback(self):  
    self.connect()
    self.connection.rollback()

  def close(self):
      if (  self.connected ) :
        self.rollback()
      self.connection =  None
      self.connected = False

  def fetchOne(self,sql,*p):
      self.connect()
      cursor= self.getCursor()
      cursor.execute(sql,*p)
      rows=cursor.fetchall()
      if ( len(rows) > 0 ):
        return rows[0]
      else:
        return None

  def executeWithHeader(self,sql, para=[] ):
    self.connect()
    retval={}
    rows= self.fetchAll(
        sql, para
    )
    retval["header"]=[]
    for d in rows[0]:
        retval["header"].append(d)
    retval["data"] = []
    for row in rows:
        retRow=[]
        for r in row:
            retRow.append(str(row[r]))
        retval["data"].append(retRow)
    return retval
