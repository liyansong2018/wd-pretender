import logging
import binascii

from core.features import Feature

from core.merge import Merger
from core.vdm.pair import Pair


class Getsign(Feature):
    def __init__(self, pair: Pair, threat_name: str) -> None:
        super().__init__(pair)
        self.threat_name = threat_name

    def run(self):
        threats = Merger(self.pair).merge()
        logging.info(f"Threats Containing: {self.threat_name}")

        for threat in threats:
            if self.threat_name.lower().encode() in threat.name.lower():
                print(f"\tthreat => {threat.name}")
                print(f"\tthreat Id => {threat.id}")
                print(f"\tsignature count => {threat.signature_counter}")
                for signature in threat.signatures:
                    print(f"\t\t {binascii.hexlify(signature.data)}")

        return None