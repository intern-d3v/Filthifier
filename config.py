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
            "mysql": {
                "easy": {},
                "medium": {},
                "hard": {}
            }



        }

        for subdirectory in os.listdir(self.srvDir)+os.listdir(self.vulnsDir):
            isService = False
            info = json.loads(
                open(self.srvDir + subdirectory + "/info.json").read())
            if info["type"] == "services": isService = True
            self.vulnerabilities[info["type"]
                                 ][info["difficulty"]][info["name"]] = formatVulns(info["name"])

    def getReqVulnerability(self):
        return self.reqVulns

    def getDistro(self):
        return self.distro

    def getAdminCount(self):
        return self.adminCount

    def getUserCount(self):
        return self.userCount

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

    def getVuln(self,type,difficulty,name):
        return self.vulnerabilities[type][difficulty][name]

    def getService(self,name, difficulty="easy"):
        return self.vulnerabilities['services'][difficulty][name]

    def getVulnCountForCategory(self, category,3556W1 diff):
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

    def getRandUserVulns(self, diff, targetLen):
        vulns = []
        tempVulns = self.getVulns("userAudit", diff)
        for i in range(targetLen):
            if len(tempVulns) == 0:
                tempVulns = self.getNextDiff(tempVulns, "userAudit", diff)
            vulns.append(random.choice(tempVulns))
        return vulns

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
                vulns.append(v)
            return self.formatVulns(vulns)

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

    def formatVuln(self, vulns, service=False):
        info = self.getInfo(i, service)
        if info["type"] == "services":
            prefix = self.srvDir
        else:
            prefix = self.vulnsDir
        dep = prefix + i + "/dependencies.tar.gz"

        return
            [
                info['description'],
                open(
                    prefix +
                    i +
                    "/check_success.sh").read(),
                open(
                    prefix +
                    i +
                    "/init_vuln.sh").read(),
                dep]

    def getNumVulns(self):
        return self.numVulns

    def getVulnCountForService(self, service, diff):
        vulns = []
        serviceNum = len(self.vulnerabilities[service][diff])
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

    def getCatWeights(self):
        return self.getDiffConfig()['categoryWeights']
