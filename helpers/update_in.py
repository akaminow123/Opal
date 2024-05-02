import json
from datetime import date
from ecdsa_sign import sign
import random

with open("verify_state_and_blind_js/input.json", "r") as in_json:
	old_in = json.load(in_json)

n = 2 #int(input("Number of buckets: "))
total_objects = 4 #int(input("Number of total objects: "))
file = "public_verify_state_and_blind_1.json" #input("Name of public file: ")

with open(file, "r") as pub_out:
	pub = json.load(pub_out)

def replace_0(lst, new):
	
	if new in lst:
		return lst

	else:
		i = lst.index("0")
		lst[i] = new
		return lst

def leak(dates, curr_date, objects, num_total, buckets):

	buckets_left = num_total;
	buckets_leaked = -1;
	i = -1;

	while (buckets_left > 0):
		i += 1
		buckets_leaked += 1
		buckets_left = min((int(curr_date) >> 4) - (int(dates[i]) >> 4), buckets_left - 1);

	new_date_added = 0
	for i in range(0, num_total):
		if (i < buckets_leaked):
			if (dates[i] > 0):
				objects[dates[i] & 15] -= 1

		if (num_total > i + buckets_leaked):
			dates[i] = dates[i + buckets_leaked]

		else:
			dates[i] = 0
		
		if (dates[i] == 0 and new_date_added == 0):
			dates[i] = int(curr_date);
			new_date_added = 1;

		if objects[dates[i] & 15] == 0:
			
			buckets[dates[i] & 15] = 0

	return dates, objects, buckets

def update_objects(bucket, all_buckets, objects):
	
	if bucket != 0:
		if bucket in all_buckets:
			objects[all_buckets.index(bucket)] = str(int(objects[all_buckets.index(bucket)]) + 1)
		else:
			objects = replace_0(objects, 1)

	return objects

if not old_in:
	new_in = {
		"sig_r" : 0,
		"sig_s_inv" : 0,
		"new_bucket" : 0,
		"new_object" : 0,
		"new_serial" : 0,
		"new_date" : 0,
		"password" : 123, #input("password"),
		"old_buckets" : [0] * n,
		"old_object_counts" : [0] * n,
		"old_serial" : 0,
		"old_dates" : [0] * total_objects,
		"r" : 5
	}


else:
	protocol = int(input("Key gen (0) or key retrieval (1)? "))

	if old_in['sig_r'] != "0" and old_in['protocol']:
		new_old_objects = update_objects(old_in['new_bucket'],
										old_in['old_buckets'],
										old_in['old_object_counts'])
		new_old_buckets = replace_0(old_in['old_buckets'], old_in['new_bucket'])
		date_var = (int(old_in['new_date']) << 4) + new_old_buckets.index(old_in['new_bucket'])
		new_old_dates, new_old_objects, new_old_buckets = leak(old_in['old_dates'], date_var, new_old_objects, 4, new_old_buckets)

	elif old_in['sig_r'] == "0":
		new_old_dates = ["0"] * total_objects
		new_old_objects = ["0"] * n
		new_old_buckets = ["0"] * n

	else:
		new_old_dates = old_in['old_dates']
		new_old_objects = old_in['old_object_counts']
		new_old_buckets = old_in['old_buckets']

	new_in = {
		"sig_r" : input("sig_r: "),
		"sig_s_inv" : input("sig_s_inv: "),
		"new_bucket" : input("New bucket: "),
		"new_object" : input("New object: "),
		"new_serial" : input("New serial: "),
		"new_date" : str(date.today()).replace("-", "")[2:],
		"password" : "123", #input("password"),
		"old_buckets" : new_old_buckets,
		"old_object_counts" : new_old_objects,
		"old_serial" : old_in['new_serial'],
		"old_dates" : new_old_dates,
		"r" : "5",
		"new_nonce" : str(random.randint(1, 2**32)),
		"protocol" : protocol
	}
	if protocol:
		new_in['old_nonce'] = input("Old nonce: ")
	else:
		new_in['old_nonce'] = new_in['new_nonce']


with open("verify_state_and_blind_js/input.json", "w") as in_json:
	json.dump(new_in, in_json)
