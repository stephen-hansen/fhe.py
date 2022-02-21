from abc import ABC, abstractmethod

class Gate(ABC):
    def __init__(self):
        self.inputConns = []

    def addInput(self, gate):
        self.inputConns.append(gate)

    def run(self):
        # TODO cache?
        inputs = []
        for gate in self.inputConns:
            inputs.append(gate.run())
        return self.runImpl(inputs)

    @abstractmethod
    def runImpl(self, inputs):
        pass

