import tarfile
import random
import os
import string


class User(object):
    def __init__(
            self,
            name,
            password="password",
            groups=[],
            hidden=False,
            strength="strong",
            authorized=True):

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
                args += i + ","
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
        if not os.path.exists("build/"): os.mkdir("build/")
        self.initFile = "build/initfile.bash"
        self.booleanFile = "build/scoreconfig.json"
        self.dependencies = []
        if "random" in self.engine.getReqVulnerability():
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
        vulns = self.engine.getReqVulnerability()
        for i in vulns:
            tmp = Insertion(self.engine.getVulnByName(i))
            self.insertions.append(tmp)
            self.dependencies.append(tmp.dependencies)
        self.initUsers()
        self.initServices()
        self.initDependencies()

    def initAllRandom(self):
        self.initUsers()
        self.initServices()
        self.initServiceVulns()
        self.initCategoryVulns()
        self.initDependencies()

    def customFormat(self, key, value, array):
        array = [
            element.format(
                **{key: value}) if key in element else element for element in array]
        return array

    def initCategoryVulns(self):
        weights = self.engine.getCatWeights()
        weights.pop('services')
        tempUsers = self.users
        # iterates over every category that is not a service
        for type in weights.keys():
            # iterates over each difficulty in each category
            for diff in self.engine.getMasterConfig()['config']['validDiffs']:
                targetVulnCount = self.engine.getVulnCountForCategory(
                    type, diff)
                if targetVulnCount > 0:  # if the category should have any vulnerabilities in it
                    for k in self.engine.getRandVulns(
                            type,
                            diff,
                            targetVulnCount):  # for each vulnerability out of those in the list output by getRandVulns

                        # below all vulnerabilities are formatted to custom
                        # standards. will implement method customFormat(key,
                        # element, array) to make easier
                        u = random.choice(tempUsers)
                        tempUsers.remove(u)
                        self.customFormat("randomUser", u.username, k)

                        self.customFormat("mainUser", self.mainUser, k)

                        name = random.choice(self.wordlist)
                        self.wordlist.remove(name)
                        self.customFormat("randomUsername", name, k)

                        # vulnerability is instantiated as Insertion object
                        tmp = Insertion(k)
                        # add to list of the image's insertions
                        self.insertions.append(tmp)
                        # add the vulnerabilities dependencies to the image's
                        # list
                        self.dependencies.append(tmp.dependencies)

    def initDependencies(self):
        with tarfile.open("build/dependencies.tar.gz", "w:gz") as tar:
            for i in self.dependencies:
                tar.add(i)

    def initServiceVulns(self):
        for i in self.reqServices:
            for j in self.engine.getMasterConfig()['config']['validDiffs']:
                if self.engine.getVulnCountForService(i, j) > 0:
                    for k in self.engine.getRandVulns(
                            i, j, self.engine.getVulnCountForService(i, j)):
                        self.insertions.append(Insertion(k))

    def initUsers(self):
        # initialize wordlist of possible usernames
        self.wordlist = [line.rstrip('\n') for line in open('names.txt')]
        # str of ascii characters for password generation
        characters = string.ascii_letters + string.digits
        userCount = self.engine.getUserCount()
        adminCount = self.engine.getAdminCount()
        for i in range(int(round(userCount))
                       ):  # iterate for each standard user we must create
            name = random.choice(self.wordlist)  # pick their name
            self.wordlist.remove(name)  # remove it from future names
            password = ''.join(
                random.choice(characters) for j in range(
                    random.randint(
                        6, 12)))  # make their password
            groups = []
            if adminCount > 0:  # if admins still must be generated, make them in sudo group
                groups = ['sudo']
                adminCount -= 1
            hidden = False  # standard users need not be hidden
            strength = "strong"  # password hash strength
            # add user object to list of users
            u = (User(name, password, groups, hidden, strength))
            if 'sudo' in groups:
                self.adminUsers.append(u)
            else:
                self.users.append(u)
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
                if j == len(self.services) - 1 and len(self.insertions) == 0:
                    end = "\n"
                f.write("\"" + i.description + "\"" + ":" + "\"" +
                        i.getScoreCmd().replace("\n", '') + "\"" + end)
            for j, i in enumerate(self.insertions):
                end = ",\n"
                if j == len(self.insertions) - 1:
                    end = "\n"
                f.write("\"" + i.description + "\"" + ":" + "\"" +
                        i.getScoreCmd().replace("\n", '') + "\"" + end)
            f.write("}\n")

    def makeScenarioFile(self):
        sTemp = """
"""
        aTemp = """
"""
        uTemp = """
"""
        for i in self.services:
            sTemp += (i.description + "\n")
        aTemp += self.mainUser.username + ":" + \
            self.mainUser.password + " (you)\n"
        tmp = self.adminUsers
        tmp.remove(self.mainUser)
        for i in tmp:
            aTemp += (i.username + ":" + i.password + "\n")
        for i in (list(set(self.users) - set(self.adminUsers))):
            uTemp += (i.username + "\n")
        self.scenario = self.scenario.format(**
                                             {
                                                 "services": sTemp,
                                                 "admins": aTemp,
                                                 "users": uTemp
                                             }
                                             )
        with open("build/scenario.txt", 'w') as f:
            f.write(self.scenario)
