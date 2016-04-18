class Network:
    def __init__(self):
        self.nodes = set()
    def addNode(self,node):
        self.nodes.add(node)
    def getNodes(self):
        retuern self.nodes

class Computer:
    def __init__(self, interactive, agree):
        self.interactive = interactive
        self.agree = agree

    def changeChoice(self, agree):
        self.agree = agree

    
