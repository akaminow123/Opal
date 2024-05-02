from flask import Flask
from flask import request, render_template, send_file, redirect, url_for
import os
import json
from ecdsa_sign import sign, mult_point

print(os.getcwd())
app = Flask(__name__, root_path=os.getcwd(), template_folder=os.getcwd())

@app.route('/', methods=["POST", "GET"])
def home():
	some = 1
	if request.method == "POST":
		
		password = ""

		with open('publics.json', "w") as public:
			public.write(request.form.to_dict()['pub'])

		with open('proof.json', "w") as proof:
			proof.write(request.form.to_dict()['proof'])

		exit = os.system("snarkjs groth16 verify verification_key_verify_state_and_blind.json publics.json proof.json")

		# print(exit)
		if exit == 0:

			pub = json.loads(request.form.to_dict()['pub'])

			with open("nonces.txt", "r") as nonce_file:

				nonces = nonce_file.read()

			if (", " + str(pub[4]) + ", ") not in nonces:

				print("HI")

				with open("nonces.txt", "a") as nonce_file:
					nonce_file.write(pub[4] + ", ")

				r, s_inv = sign(int(pub[0]), int(pub[3]))

				k = 91564559347567415298549879341628253121288674994757533967340008315496314

				password = mult_point(int(pub[1]), int(pub[2]), k)

				password = str(password[0]) + ',' + str(password[1])

				with open("serials.txt", "r") as serial_file:

					serials = serial_file.read()
					
				if (", " + str(pub[5]) + ", ") not in serials or pub[5] == "0":

					with open("serials.txt", "a") as serial_file:

						serial_file.write(", " + str(pub[5]))

					r, s_inv = sign(int(pub[0]), int(pub[3]))

					k = 91564559347567415298549879341628253121288674994757533967340008315496314

					password = mult_point(int(pub[1]), int(pub[2]), k)

					password = str(password[0]) + ',' + str(password[1])

					return render_template('rate_limiting.html', password=password, r=r, s_inv=s_inv)

				else:

					alert = "The serial number you provided has already been used. Please select a new serial number."

					return render_template('rate_limiting.html', alert=alert)
			else:

				alert = "The nonce you provided has already been used. Please select a new nonce."

				return render_template('rate_limiting.html', alert=alert)

		else:

			alert = "Your proof did not verify correctly. Please update your proof."
			
			return render_template('rate_limiting.html', alert=alert)
		

	# if request.method == "GET":
	return render_template('rate_limiting.html', password="")

@app.route('/submitted/<password>')
def submitted(password):
	return 'Hello %s as Guest' % password

@app.route('/verify_state_and_blind.wasm')
def download_wasm():
	return send_file('verify_state_and_blind.wasm')

@app.route('/verify_state_and_blind_0001.zkey')
def download_zkey():
	return send_file('verify_state_and_blind_0001.zkey')

@app.route('/verification_key_verify_state_and_blind.json')
def download_ver():
	return send_file('verification_key_verify_state_and_blind.json')

# @app.route('/submit', methods=["POST"])
# def submit():
# 	return render_template('submit.php')

app.run()