import json
import random
import os


class ConfigEngine():
    """
    A class to read input from several configurations and format them when
    accessor methods are called

    Attributes
    ----------
    vulnsDir : str
        The directory path where all vulnerability configurations are stored
    srvDir : str
        The directory path where all service configurations are stored
    masterConfig : dict
        The loaded json configuration of the 'config.json' file equivalent
    prefConfig : dict
        The loaded json configuration of the 'prefs.json' file equivalent
    difficulty : str
        The difficulty of the image. Valid options are the keys of 'validDifficulties' within masterConfig
    reqVulns : list
        The value of 'vulnerabilities' in prefConfig
    numVulns : int
        The number of vulnerabilities to be implemented on a random image
    distro : str
        The 'os' field read from prefConfig
    userCount : int
        The amount of users to be added to the image
    adminCount : int
        The amount of users in userCount which will be added as admins
    vulnerabilities : dict (3d)
        The dictionary containing all loaded vulnerabilities.
        Formatted as vulnerabilities[category][difficiculty][name]

    Methods
    -------
    getReqVulnerability()
        Accessor method for reqVulns
    getDistro()
        Accessor method for distro
    getAdminCount()
        Accessor method for adminCount
    getUserCount()
        Accessor method for userCount
    getNumVulns()
        Accessor method for numVulns
    getDifficulty()
        Accessor method for difficulty
    getPrefConfig()
        Accessor method for prefConfig
    getMasterConfig()
        Accessor method for masterConfig
    getDiffConfig()
        Returns the dict value in masterConfig for difficulty
    getReqServices()
        Returns the list of services stored in 'services' key in prefConfig
    getVulns(type,difficulty)
        Returns dict vulnerabilities[type][difficulty] - another dict full of vuln names as keys and a list of config data as values
    getVuln(type,difficulty,name)
        Returns list vulnerabilities[type][difficulty] - better if you need exactly one vulnerability config and know the name
    getVulnByName(self,name)
        Finds the list within vulnerabilities in the third dimension that has a key of name
    getValidDifficulties()
        Returns dict at 'validDifficulties' key in masterConfig
    getCatWeights()
        Returns the 'categoryWeights' key in masterConfig for difficulty
    getServiceWeight()
        Returns only the 'services' value in getCatWeights()
    getService(mame
    """

    def __init__(
            self,
            mconf="config.json",
            pconf="prefs.json",
            vDir="vulnerabilities/",
            sDir="services/"):

        masterConfigPath = mconf
        prefConfigPath = pconf
        self.vulnsDir = vDir
        self.srvDir = sDir
        self.masterConfig = json.load(open(masterConfigPath))
        self.prefConfig = json.load(open(prefConfigPath))
        selection = self.prefConfig['config']['difficulty']
        if selection == "*":
            selection = random.choice(
                self.masterConfig['config']['validDifficulties'].keys())
        self.difficulty = selection
        self.reqVulns = self.prefConfig['config']['vulnerabilities']
        self.numVulns = random.randint(
            self.getDiffConfig()['minbound'], self.getDiffConfig()['maxbound'])
        self.distro = self.prefConfig['config']['os']
        self.userCount = random.randint(
            self.getDiffConfig()['minUsers'],
            self.getDiffConfig()['maxUsers']
        )
        adminPercent = self.getDiffConfig()['percentAdmins']
        self.adminCount = int(round(self.userCount * adminPercent))

        self.vulnerabilities = {
            "userAudit": {
                "easy": {},
                "medium": {},
                "hard": {}
            },
            "loginPolicy": {
                "easy": {},
                "medium": {},
                "hard": {}
            },
            "securityAudit": {
                "easy": {},
                "medium": {},
                "hard": {}
            },
            "services": {
                "easy": {},
                "medium": {},
                "hard": {}
            },
            "unauthorizedSoftware": {
                "easy": {},
                "medium": {},
                "hard": {}
            },
            "kernelAudit": {
                "easy": {},
                "medium": {},
                "hard": {}
            },
            "sshd": {
                "easy": {},
                "medium": {},
                "hard": {}
            },
            "apache2": {
                "easy": {},
                "medium": {},
                "hard": {}
            },
            "mysql_server": {
                "easy": {},
                "medium": {},
                "hard": {}
            }



        }

        for subdirectory in os.listdir(
                self.srvDir) + os.listdir(self.vulnsDir):
            isService = False
            prefix = self.vulnsDir
            if subdirectory in os.listdir(self.srvDir):
                isService = True
                prefix = self.srvDir
            info = json.loads(
                open(prefix + subdirectory + "/info.json").read())
            self.vulnerabilities[info["type"]][info["difficulty"]
                                               ][info["name"]] = self.formatVuln(info["name"], isService)

    def getReqVulnerability(self):
        return self.reqVulns

    def getDistro(self):
        return self.distro

    def getAdminCount(self):
        return self.adminCount

    def getUserCount(self):
        return self.userCount

    def getNumVulns(self):
        return self.numVulns

    def getDifficulty(self):
        return self.difficulty

    def getPrefConfig(self):
        return self.prefConfig

    def getMasterConfig(self):
        return self.masterConfig

    def getDiffConfig(self):
        return self.masterConfig['config']['validDifficulties'][self.getDifficulty(
        )]

    def getReqServices(self):
        return self.prefConfig['config']['services']

    def getVulns(self, type, difficulty, name=""):
        return self.vulnerabilities[type][difficulty]

    def getVuln(self, cat, difficulty, name):
        return self.getVulns(type,difficulty)[name]

    def getVulnByName(self, name):
        for cat in self.vulnerabilities.values():
            for diff in cat.values():
                for key in diff.keys():
                    if name == key:
                        return diff[name]

    def getValidDifficulties(self):
        return self.masterConfig['config']['validDifficulties']

    def getCatWeights(self):
        return self.getDiffConfig()['categoryWeights']

    def getServiceWeight(self):
        return self.getCatWeights['services']

    def getService(self, name, difficulty="easy"):
        return self.vulnerabilities['services'][difficulty][name]

    def getInfo(self, vuln_name, service=False):  # returns dictionary
        if service:
            prefix = self.srvDir
        else:
            prefix = self.vulnsDir
        info = json.loads(
            open(prefix + vuln_name + "/info.json").read())
        return info

    def getVulnCountForCategory(self, category, diff):
        percent = (
            (1.0 *
             self.getDiffConfig()['categoryWeights'][category] *
             self.getNumVulns() *
             self.getDiffConfig()['difficultyWeight'][diff]))
        return int(round(percent))

    def getRandVulns(self, type, diff, targetLen):
        vulns = []
        diffs = self.masterConfig['config']['validDiffs']
        if len(vulns) < targetLen:
            tempVulns = self.getVulns(type, diff)
            while (len(vulns) < targetLen):
                tempVulns = self.getNextDiff(tempVulns, type, diff)
                if tempVulns == -1:
                    print "u need more shit on " + type + ", lvl: " + diff
                v = random.choice(tempVulns)
                tempVulns.remove(v)
                vulns.append(self.vulnerabilities[type][diff][v])
            return vulns

    def getNextDiff(self, tempVulns, type, diff):
        diffs = self.masterConfig['config']['validDiffs']
        if len(tempVulns) == 0:
            if diffs.index(diff) == len(diffs) - 1:
                return -1
            nextDiff = diffs[diffs.index(diff) + 1]
            return self.getNextDiff(
                self.getVulns(
                    type,
                    nextDiff),
                type,
                nextDiff)
        else:
            return tempVulns

    def formatVuln(self, name, service=False):
        info = self.getInfo(name, service)
        if info["type"] == "services":
            prefix = self.srvDir
        else:
            prefix = self.vulnsDir
        dep = prefix + name + "/dependencies.tar.gz"
        if not os.path.exists(dep):
            dep = None

        return [
            info['description'],
            open(
                prefix +
                name +
                "/check_success.sh").read(),
            open(
                prefix +
                name +
                "/init_vuln.sh").read(),
            dep]

    def getVulnCountForService(self, service, diff):  # sum hardcore math
        vulns = []
        serviceNum = len(self.getVulns(service, diff))
        totalNum = 0.0
        for srv in self.getReqServices():
            totalNum += len(self.getVulns(srv, diff))
        serviceAtDiffCount = len(self.getVulns(service, diff))
        serviceWeight = self.getValidDifficulties(
        )[self.getDifficulty()]['categoryWeights']['services']
        nVulns = self.getNumVulns()
        diffWeight = self.getValidDifficulties(
        )[self.getDifficulty()]['categoryWeights']['services']
        percent = (
            ((1.0 *
              serviceAtDiffCount /
              totalNum *
              serviceWeight *
              nVulns *
              diffWeight)))
        return int(round(percent))
