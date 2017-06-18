import mailbox
import sys
import json
import re

inboxes = {}
try:
	inboxnm = sys.argv[1]
except IndexError:
	print 'There is only one way to use this. Run ./{} [MBOX Filename] and you will get a file [MBOX Filename].json.'.format(sys.argv[0])
	exit(1)



# Create top-level JSON index
inboxes[inboxnm] = {}

# Set the filename as write location
writelocation = "{}{}".format(inboxnm,'.json')
# Open the filename for writing
target = open(writelocation, 'w')

msg = 0
# Iterate through Mailbox message by message
for message in mailbox.mbox(inboxnm):
	# Strip newlines gracefully to store in object
	messagecontent = " ".join((str(message).splitlines()))
	# Get all header keys
	keylst = message.keys()

	# Create JSON array on a per-message basis
	inboxes[inboxnm][msg] = {}

	# Iterate through headers
	for key in keylst:
		# Store headers key-by-key
		inboxes[inboxnm][msg][key] = message[key]

	# Store raw content
	# This is useful for both referencing the body and if I missed something
	inboxes[inboxnm][msg]['rawcontent'] = messagecontent

	# Add 1 to msg ID
	msg = msg+1

target.write(json.dumps(inboxes))