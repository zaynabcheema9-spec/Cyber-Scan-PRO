import nmap


class NetworkScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan(self, target):
        self.scanner.scan(
            hosts=target,
            arguments="-sV -T4"
        )

        return self.scanner