import json
import random
import os


class ConfigEngine():
    def __init__(self, mconf="config.json", pconf="prefs.json"):
        self.masterConfigPath = mconf
        self.prefConfigPath = pconf
        self.vulnsDir = "vulnerabilities/"
        self.srvDir="services/"
        self.masterConfig = json.load(open(self.masterConfigPath))
        self.prefConfig = json.load(open(self.prefConfigPath))
        selection = self.prefConfig['config']['difficulty']
        if selection == "*":
            selection = random.choice(
                self.masterConfig['config']['validDifficulties'].keys())
        self.reqVulns = self.prefConfig['config']['vulnerabilities']
        self.difficulty = selection
        self.numVulns = random.randint(
            self.getDiffConfig()['minbound'], self.getDiffConfig()['maxbound'])
        self.distro = self.prefConfig['config']['os']
        self.userCount = random.randint(
            self.getDiffConfig()['minUsers'],
            self.getDiffConfig()['maxUsers']
        )
        self.adminPercent = self.getDiffConfig()['percentAdmins']
        self.adminCount = self.userCount * self.adminPercent

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

        for subdirectory in os.listdir(self.srvDir)+os.listdir(self.vulnsDir):
            isService=False
            prefix=self.vulnsDir
            if subdirectory in os.listdir(self.srvDir):
                isService=True
                prefix=self.srvDir
            info = json.loads(
                open(prefix + subdirectory + "/info.json").read())
            self.vulnerabilities[info["type"]
                                 ][info["difficulty"]][info["name"]] = self.formatVuln(info["name"],isService)

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

    def getCatWeights(self):
        return self.getDiffConfig()['categoryWeights']

    def getDifficulty(self):
        return self.difficulty

    def getDiffConfig(self):
        return self.masterConfig['config']['validDifficulties'][self.getDifficulty(
        )]

    def getInfo(self, vuln_name, service=False):  # returns dictionary
        if service:
            prefix = self.srvDir
        else:
            prefix=self.vulnsDir
        info = json.loads(
            open(prefix + vuln_name + "/info.json").read())
        return info

    def getVulns(self, type, difficulty, name=""):
        return self.vulnerabilities[type][difficulty]

    def getVuln(self,cat,difficulty,name):
        return self.vulnerabilities[cat][difficulty][name]

    def getVulnByName(self,name):
        for cat in self.vulnerabilities.values():
            for diff in cat.values():
                for key in diff.keys():
                    if name == key: return diff[name]

    def getService(self,name, difficulty="easy"):
        return self.vulnerabilities['services'][difficulty][name]

    def getVulnCountForCategory(self, category,diff):
        percent = (
            (1.0 *
             self.getDiffConfig()['categoryWeights'][category] *
             self.getNumVulns() *
             self.getDiffConfig()['difficultyWeight'][diff]))
        return int(round(percent))

    def getValidDifficulties(self):
        return self.masterConfig['config']['validDifficulties']

    def getServiceWeight(self):
        return self.getDiffConfig()['categoryWeights']['services']

    def getPrefConfig(self):
        return self.prefConfig

    def getMasterConfig(self):
        return self.masterConfig

    def getReqServices(self):
        return self.prefConfig['config']['services']

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

    def getVulnCountForService(self, service, diff): #sum hardcore math
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

