import tarfile
import random
import os
import string

class User(object):
   def __init__(self,name,password="password",groups=[],hidden=False,strength="strong",authorized=True):
      self.username=name
      self.password=password
      self.groups=groups
      self.isHidden=hidden
      if strength=="weak":
         self.encryption="md5"
      else:
         self.encryption="sha512"
      self.authorized=authorized

   def getInitCmd(self):
      if self.isHidden:
         args="-r -M -N -o "
      else:
         args="-m "
      if len(self.groups)>0:
         args+="-G "
         for i in self.groups:
            args+=i+","
         if args[-1]==",":args=args[:-1]
      adduser="useradd %s -s '/bin/bash' -p $(mkpasswd --method=%s %s) %s" % (self.username,self.encryption,self.password,args)
      return adduser

class Insertion(object): #abstract class for any change made to image.
   def __init__(self,conf): #conf is the array for the insertion in the vulns.json file
      self.description=conf[0]
      self.scoringBoolean=conf[1]
      self.initCommand=conf[2]
      self.dependencies=conf[-1]
#      if len(conf)==4: self.arguments=conf[3]

   def getScoreCmd(self):
      return self.scoringBoolean

   def getDescription(self):
      return self.description

   def getInitCmd(self):
      return self.initCommand

   def initialize(self):
      os.system(initCommand)

class Vuln(Insertion): #(probably an subclass of Insertion) a vulnerability
   pass

class Service(Insertion): #("") a service
   def __init__(self,conf):
      super(Service,self).__init__(conf)


class Package(Insertion): #("") a package
   pass

class Image(): #a virtual machine image
   def __init__(self,configEngine):
      self.engine=configEngine

      self.numVulns=self.engine.getNumVulns()
      self.distro=self.engine.getDistro()
      self.difficulty=self.engine.getDifficulty()
      self.reqServices=self.engine.getReqServices()
      self.services=[]
      self.insertions=[]
      self.users=[]
      self.adminUsers=[]
      self.mainUser=""
      self.initFile="build/initfile.bash"
      self.booleanFile="build/scoreconfig.bash"
      self.dependencies=[]

      self.initAll()
      self.scenario="""

<Insert Default Scenario Template Here>

Required Services:
{services}

Authorized Admins:
{admins}

Authorized Users:
{users}
"""

   def initAll(self):
      self.initUsers()
      self.initServices()
      self.initServiceVulns()
      self.initCategoryVulns()
      self.initDependencies()
   def initCategoryVulns(self):
      weights=self.engine.getCatWeights()
      weights.pop('services')
      tempUsers=self.users
      for i in weights.keys():
         for j in self.engine.getMasterConfig()['config']['validDiffs']:
           #print i,j
            if self.engine.getVulnCountForCategory(i,j)>0:
               #print self.engine.getVulnCountForCategory(i,j)
               if i!="userAudit":
                  for k in self.engine.getRandVulns(i,j,self.engine.getVulnCountForCategory(i,j)):
                     tmp=Insertion(k)
                     self.dependencies.append(tmp.dependencies)
                     self.insertions.append(tmp)
               else:
                  for k in self.engine.getRandUserVulns(j,self.engine.getVulnCountForCategory(i,j)):
                     if "%s" in k:
                        u=random.choice(tempUsers)
                        tempUsers.remove(u)
                        conf=[user % u.username for user in k]
                        self.insertions.append(Insertion(conf))
                     else:
                        self.insertions.append(Insertion(k))

   def initDependencies(self):
      #filelist = [ f for f in os.listdir("./archive/") ]
      #for f in filelist:
      #   os.remove(os.path.join("./archive/", f))
      with tarfile.open("./build/dependencies.tar.gz", "w:gz") as tar:
         for i in self.dependencies:
            print i
            tar.add(i)
   def initServiceVulns(self):
      for i in self.reqServices:
         for j in self.engine.getMasterConfig()['config']['validDiffs']:
            if self.engine.getVulnCountForService(i,j)>0:
               #print self.engine.getVulnCountForService(i,j)
               for k in self.engine.getRandVulns(i,j,self.engine.getVulnCountForService(i,j)):
                  self.insertions.append(Insertion(k))

   def initUsers(self):
      wordlist=[line.rstrip('\n') for line in open('names.txt')]
      characters=string.ascii_letters+string.digits
      for i in range(int(round(self.engine.getUserCount()*.8))):
         name=random.choice(wordlist)
         wordlist.remove(name)
         password=''.join(random.choice(characters) for j in range(random.randint(6,12)))
         groups=[]
         hidden=False
         strength="strong"
         self.users.append(User(name,password,groups,hidden,strength))
      for i in range(int(round(self.engine.getUserCount()*.2))):
         name=random.choice(wordlist)
         wordlist.remove(name)
         password=''.join(random.choice(characters) for j in range(random.randint(6,12)))
         groups=['sudo']
         hidden=False
         strength="strong"
         u=(User(name,password,groups,hidden,strength))
         self.users.append(u)
         self.adminUsers.append(u)
      self.mainUser=random.choice(self.adminUsers)

   def initServices(self):
      for i in self.reqServices:
         self.services.append(Service(self.engine.getService(i)))

   def getInsertions(self):
      return self.insertions

   def makeInitFile(self):
      with open(self.initFile,"w") as f:
         f.write("""#!/bin/bash\n""")
         for i in self.users:
            f.write(i.getInitCmd())
            f.write("\n")
         for i in self.services:
            f.write(i.getInitCmd())
            f.write("\n")
         for i in self.insertions:
            f.write(i.getInitCmd())
            f.write("\n")
      return f

   def makeScoreFile(self):
      with open(self.booleanFile,"w") as f:
         for i in self.services:
            f.write(i.getScoreCmd()+"\n")
         for i in self.insertions:
            f.write(i.getScoreCmd()+"\n")

   def makeScenarioFile(self):
      sTemp="""
"""
      aTemp="""
"""
      uTemp="""
"""
      for i in self.services:
         sTemp+=(i.description+"\n")
      aTemp+=self.mainUser.username+":"+self.mainUser.password+" (you)"
      for i in self.adminUsers:
         aTemp+=(i.username+":"+i.password+"\n")
      for i in (list(set(self.users)-set(self.adminUsers))):
         uTemp+=(i.username+"\n")
      self.scenario=self.scenario.format(**
         {
            "services":sTemp,
            "admins":aTemp,
            "users":uTemp
         }
      )
      with open("build/scenario.txt",'w') as f:
         f.write(self.scenario)
