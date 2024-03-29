from image_resrc import *
from config import *
import sys

prefConfig = "prefs.json"
hardConfig = "config.json"


def main():
    Configurer = ConfigEngine(hardConfig, prefConfig)
    vm = Image(Configurer)
    vm.makeInitFile()
    vm.makeScoreFile()
    vm.makeScenarioFile()


# the below is only relevant to nathan prouse
'''
    beginTemplate = """
{
	"teams":{
		"test": "Test Team"
	},
	"linux":{
   """
    midTemplate = """
		"{num}":["{description}",{value},"{boolean}"],
   """
    endTemplate = """
	}
}
   """

    for i, j in enumerate(vm.getInsertions()):
        if i + 1 == len(vm.getInsertions()):
            midTemplate = midTemplate[:-5]
        beginTemplate += midTemplate.format(
            **{
                "num": i + 1,
                "description": j.getDescription(),
                "value": 0,
                "boolean": j.getScoreCmd()
            }
        )
    beginTemplate += endTemplate

    with open("build/server.json", "w") as f:
        f.write(beginTemplate)
        f.close()
'''

if __name__ == "__main__":
    main()
