
import random
import datetime

n = 2736030358979909402780800718157159386076813972158567259200215660948447373041
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def add_point(x1, y1, x2, y2):
	a = 168700
	d = 168696
	x3 = ((x1*y2 + y1*x2) % p) * pow((1 + d*x1*x2*y1*y2), -1, p) % p
	y3 = ((y1*y2 - a*x1*x2) % p) * pow((1 - d*x1*x2*y1*y2), -1, p) % p

	return [x3, y3]

def mult_point(x, y, r):
	point = (0, 1)
	powers = []
	powers.append([x, y])
	for i in range(1, 256):
		powers.append(add_point(powers[i-1][0], powers[i-1][1], powers[i-1][0], powers[i-1][1]))

	for i in range(256):
		if (r & 1):
			point = add_point(point[0], point[1], powers[i][0], powers[i][1])
		r >>= 1

	return point

def sign(hashed_msg, date):

	print(hashed_msg)
	print(date)

	# COMMENT OUT ASSERT FOR TESTING

	# assert (date == str(datetime.date.today()).replace('-', '')[2:])

	hashed_msg = int(hashed_msg) >> 6

	G = [0,0]
	G[0] = 5299619240641551281634865583518297030282874472190772894086521144482721001553
	G[1] = 16950150798460657717958625567821834550301663161624707787222815936182638968203
	
	d = 91564559347567415298549879341628253121288674994757533967340008315496314
	ped_key = 234213641236749123845908134750891237498123874098123758921375127638
	k_inv = 0
	r_inv = 0

	while k_inv == 0 or s_inv == 0:
	    try: 
	        k = random.randint(1, 2**251-1)
	        k_inv = pow(k, -1, n)
	        r = mult_point(G[0], G[1], k)[0] % n
	        s = k_inv*(hashed_msg + d*r) % n
	        s_inv = pow(s, -1, n)
	   
	    except:
	        pass

	return (r, s_inv)