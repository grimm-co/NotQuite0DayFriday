import argparse, os, socket, sys, time, threading
from exploit import address_info, ftp_devices, main

###########################################################################
## Test Functions #########################################################
###########################################################################

class FakeArgs(object):
	def __init__(self, model, version):
		self.model = model
		self.version = version
		self.command = "START_TELNET"
		self.local_ip = "127.0.0.1"
		self.version_only = False
		self.csrf = False

	def should_test(self):
		return True

	def test(self):
		if self.should_test():
			main(self)

class FileArgs(FakeArgs):
	def __init__(self, model, version, directory):
		super(FileArgs, self).__init__(model, version)
		self.file = True
		self.ip = os.path.join(directory, "{}_{}".format(model, version))

class NetworkArgs(FakeArgs):
	def __init__(self, model, version, port):
		super(NetworkArgs, self).__init__(model, version)
		self.file = False
		self.ip = "127.0.0.1"
		self.https = False
		self.port = port

	def should_test(self):
		return self.model not in ftp_devices

server_open = False
should_stop_thread = False
def listener_thread(port):
	global server_open, should_stop_thread

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(("127.0.0.1", port))
	sock.listen(1000)
	server_open = True

	while not should_stop_thread:
		client, client_address = sock.accept()
		data = ""
		while True:
			char = client.recv(1)
			data += char
			if data.endswith("\r\n\r\n"):
				break

		content_length = None
		for line in data.split("\r\n"):
			if line.startswith("Content-Length:"):
				content_length = int(line.split(":")[1].strip())
				break

		if content_length != None:
			data = ""
			while True:
				char = client.recv(1)
				data += char
				if len(data) < content_length:
					break

		client.close()

def start_listener(port):
	global server_open

	thread = threading.Thread(target=listener_thread, args=[port])
	thread.start()
	while not server_open:
		time.sleep(0.01)
	return thread

def stop_listener():
	global should_stop_thread
	should_stop_thread = True

###########################################################################
## Main Execution #########################################################
###########################################################################

parser = argparse.ArgumentParser(description='Test the exploit')
parser.add_argument('directory', type=str, help='The directory to write the exploit files to')
parser.add_argument('-file_only', required=False, action='store_true', help='Only run the file tests')
parser.add_argument('-model', type=str, help='The model to test (default all models)')
parser.add_argument('-port', type=int, default=8888, help='The port to test the exploit on')
args = parser.parse_args()

# Start a listener for the network tests
if not args.file_only:
	start_listener(args.port)

# Create the diectory for the file tests
if not os.path.exists(args.directory):
	os.mkdir(args.directory)

if args.model != None:
	models = [args.model.upper()]
else:
	models = address_info.keys()
	models.sort()

for model in models:
	print("Testing {}".format(model))
	for version in address_info[model].keys():
		fa = FileArgs(model, version, args.directory)
		fa.test()

		if not args.file_only:
			na = NetworkArgs(model, version, args.port)
			na.test()

stop_listener()
