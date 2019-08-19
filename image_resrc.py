import tarfile
import random
import os
import string


class User(object):
    def __init__(self, name, password="password", groups=[], hidden=False, strength="strong", authorized=True):
        self.username = name
        self.password = password
        self.groups = groups
        self.isHidden = hidden
        if strength == "weak":
            self.encryption = "md5"
        else:
            self.encryption = "sha512"
        self.authorized = authorized

    def getInitCmd(self):
        if self.isHidden:
            args = "-r -M -N -o "
        else:
            args = "-m "
        if len(self.groups) > 0:
            args += "-G "
            for i in self.groups:
                args += i+","
            if args[-1] == ",":
                args = args[:-1]
        adduser = "useradd %s -s '/bin/bash' -p $(mkpasswd --method=%s %s) %s" % (
            self.username, self.encryption, self.password, args)
        return adduser


class Insertion(object):  # abstract class for any change made to image.
    def __init__(self, conf):  # conf is the array for the insertion in the vulns.json file
        self.description = conf[0]
        self.scoringBoolean = conf[1]
        self.initCommand = conf[2]
        self.dependencies = conf[-1]

    def getScoreCmd(self):
        return self.scoringBoolean

    def getDescription(self):
        return self.description

    def getInitCmd(self):
        return self.initCommand

    def initialize(self):
        os.system(initCommand)



class Service(Insertion):
    def __init__(self, conf):
        super(Service, self).__init__(conf)

class Image():  # a virtual machine image
    def __init__(self, configEngine):
        self.engine = configEngine

        self.numVulns = self.engine.getNumVulns()
        self.distro = self.engine.getDistro()
        self.difficulty = self.engine.getDifficulty()
        self.reqServices = self.engine.getReqServices()
        self.services = []
        self.insertions = []
        self.users = []
        self.adminUsers = []
        self.mainUser = ""
        self.initFile = "build/initfile.bash"
        self.booleanFile = "build/scoreconfig.json"
        self.dependencies = []
        if "random" in self.engine.getVulnerability():
            self.initAllRandom()
        else:
            self.initImage()
        self.scenario = """

<Insert Default Scenario Template Here>

Required Services:
{services}

Authorized Admins:
{admins}

Authorized Users:
{users}
"""

    def initImage(self):
        vulns = self.engine.getVulnerability()
        for i in self.engine.formatVulns(vulns):
            tmp = Insertion(i)
            self.insertions.append(tmp)
            self.dependencies.append(tmp.dependencies)
        self.initUsers()
        self.initServices()
#      self.initDependencies()

    def initAllRandom(self):
        self.initUsers()
        self.initServices()
        self.initServiceVulns()
        self.initCategoryVulns()
        # self.initDependencies()

    def initCategoryVulns(self):
        weights = self.engine.getCatWeights()
        weights.pop('services')
        tempUsers = self.users
        for i in weights.keys():
            for j in self.engine.getMasterConfig()['config']['validDiffs']:
                if self.engine.getVulnCountForCategory(i, j) > 0:
                    for k in self.engine.getRandVulns(i, j, self.engine.getVulnCountForCategory(i, j)):
                        if any("{randomUser}" in l for l in k):
                            u = random.choice(tempUsers)
                            tempUsers.remove(u)
                            context = {"randomUser": u.username}
                            k = [line.format(
                                **context) if "{randomUser}" else line in line for line in k]
                        if any("{mainUser}" in l for l in k):
                            k = [line.format(
                                **{"mainUser": self.mainUser}) if "{mainUser}" else line in line for line in k]
                        if any("{randomUsername}" in l for l in k):
                            name = random.choice(self.wordlist)
                            self.wordlist.remove(name)
                            k = [line.format(
                                **{"randomUsername": name}) if "{randomUserName}" in line else line for line in k]
                        tmp = Insertion(k)
                        self.insertions.append(tmp)
                        self.dependencies.append(tmp.dependencies)

    def initDependencies(self):
        with tarfile.open("./build/dependencies.tar.gz", "w:gz") as tar:
            for i in self.dependencies:
                tar.add(i)

    def initServiceVulns(self):
        for i in self.reqServices:
            for j in self.engine.getMasterConfig()['config']['validDiffs']:
                if self.engine.getVulnCountForService(i, j) > 0:
                    for k in self.engine.getRandVulns(i, j, self.engine.getVulnCountForService(i, j)):
                        self.insertions.append(Insertion(k))

    def initUsers(self):
        self.wordlist = [line.rstrip('\n') for line in open('names.txt')]
        characters = string.ascii_letters+string.digits
        for i in range(int(round(self.engine.getUserCount()*.8))):
            name = random.choice(self.wordlist)
            self.wordlist.remove(name)
            password = ''.join(random.choice(characters)
                               for j in range(random.randint(6, 12)))
            groups = []
            hidden = False
            strength = "strong"
            self.users.append(User(name, password, groups, hidden, strength))
        for i in range(int(round(self.engine.getUserCount()*.2))):
            name = random.choice(self.wordlist)
            self.wordlist.remove(name)
            password = ''.join(random.choice(characters)
                               for j in range(random.randint(6, 12)))
            groups = ['sudo']
            hidden = False
            strength = "strong"
            u = (User(name, password, groups, hidden, strength))
            self.users.append(u)
            self.adminUsers.append(u)
        self.mainUser = random.choice(self.adminUsers)

    def initServices(self):
        for i in self.reqServices:
            self.services.append(Service(self.engine.getService(i)))

    def getInsertions(self):
        return self.insertions

    def makeInitFile(self):
        with open(self.initFile, "w") as f:
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
        with open(self.booleanFile, "w") as f:
            f.write("{\n")
            for j, i in enumerate(self.services):
                end = ",\n"
                if j == len(self.services)-1 and len(self.insertions) == 0:
                    end = "\n"
                f.write("\""+i.description+"\""+":"+"\"" +
                        i.getScoreCmd().replace("\n", '')+"\""+end)
            for j, i in enumerate(self.insertions):
                end = ",\n"
                if j == len(self.insertions)-1:
                    end = "\n"
                f.write("\""+i.description+"\""+":"+"\"" +
                        i.getScoreCmd().replace("\n", '')+"\""+end)
            f.write("}\n")

    def makeScenarioFile(self):
        sTemp = """
"""
        aTemp = """
"""
        uTemp = """
"""
        for i in self.services:
            sTemp += (i.description+"\n")
        aTemp += self.mainUser.username+":"+self.mainUser.password+" (you)\n"
        tmp = self.adminUsers
        tmp.remove(self.mainUser)
        for i in tmp:
            aTemp += (i.username+":"+i.password+"\n")
        for i in (list(set(self.users)-set(self.adminUsers))):
            uTemp += (i.username+"\n")
        self.scenario = self.scenario.format(**
                                             {
                                                 "services": sTemp,
                                                 "admins": aTemp,
                                                 "users": uTemp
                                             }
                                             )
        with open("build/scenario.txt", 'w') as f:
            f.write(self.scenario)

    def recursiveFormat(self, array, dict):
        for element in array:
            if type(element) is str:
                array[array.index(element)] = element.format(**dict)
            else:
                array[array.index(element)] = self.recursiveFormat(
                    element, dict)
        return array
