class IP:
    def __init__(self, address, name):
        self.address = address
        self.name = name

    def __str__(self):
        return ("%s, %s") % (self.address, self.name)

