# Security Access in Service 27

# Fixed bytes
F1 = 0x41
F2 = 0xAA
F3 = 0x42
F4 = 0xBB
F5 = 0x43

# Seed bytes
S1 = 0x1A
S2 = 0xF9
S3 = 0x64

# Initial Value 
IV = 0xC541A9

FB = (F5 << 32) | (F4 << 24) | (F3 << 16) | (F2 << 8) | F1
SB = (S3 << 16) | (S2 << 8) | S1

class crypto_security_access():
	def __init__(self, fixedBytes, seedBytes, initialValue=0xC541A9):
		self.initialValue = self.__hex2array__(initialValue,24)
		self.fixedBytes = self.__hex2array__(fixedBytes,40)
		self.seedBytes = self.__hex2array__(seedBytes,24)
		self.nextChangeBits = self.fixedBytes + self.seedBytes
		self.positiona = self.initialValue
		self.positionb = []
		self.positionc = []

	def __hex2array__(self, tmp, length):
		arr = []
		for i in range(length):
			arr.insert(0,tmp & 0x1)
			tmp = tmp >> 1
		return arr

	def encrypt(self):
		self.positionb = [self.positiona.pop() ^ self.nextChangeBits.pop()] + self.positiona
		self.positionc = self.positionb
		self.positionc[3] = self.positionb[0] ^ self.positionc[3]
		self.positionc[8] = self.positionb[0] ^ self.positionc[8]
		self.positionc[11] = self.positionb[0] ^ self.positionc[11]
		self.positionc[18] = self.positionb[0] ^ self.positionc[18]
		self.positionc[20] = self.positionb[0] ^ self.positionc[20]
		self.positiona = self.positionc

	def __array2hex__(self, tmp):
		result = 0
		for i in range(7,-1,-1):
			result = tmp[7-i] << i | result
		return result

	def generate(self):
		responseByte = self.positionc[::-1]
		responseByte1inBinary = responseByte[4:12][::-1]
		responseByte2inBinary = responseByte[12:16][::-1] + responseByte[20:24][::-1]
		responseByte3inBinary = responseByte[0:4][::-1] + responseByte[16:20][::-1]
		responseByte1inBinary = self.__array2hex__(responseByte1inBinary)
		responseByte2inBinary = self.__array2hex__(responseByte2inBinary)
		responseByte3inBinary = self.__array2hex__(responseByte3inBinary)
		return [responseByte1inBinary,responseByte2inBinary,responseByte3inBinary]

test = crypto_security_access(FB,SB)
for i in range(64):
	test.encrypt()
result = test.generate()
for i in result:
	print(hex(i))

