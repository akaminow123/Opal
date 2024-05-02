include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/sha256/sha256.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/pedersen.circom";

// PRIVATE KEY = 91564559347567415298549879341628253121288674994757533967340008315496314

//Multiply (a*b mod m)
function mod_mult(a, b, m) {
	var res = 0;

	while (b > 0) {

		if (b & 1) {
			res = (res + a) % m;
		}

		a = (2 * a) % m;
		b >>= 1;
	}

	return res;
}

//Add two points in the BabyJubJub Curve
function add_point(x1, y1, x2, y2) {

	var a = 168700;
	var d = 168696;
	var x3 = (x1*y2 + y1*x2) * 1 / (1 + d*x1*x2*y1*y2);
	var y3 = (y1*y2 - a*x1*x2) * 1 / (1 - d*x1*x2*y1*y2);

	return [x3, y3];
}

//Multiple a point by a scalar in BabyJubJub
function mult_point(x, y, r){

	var point[2];
	var powers[512];

	point = [0, 1];
	powers[0] = x;
	powers[1] = y;

	for (var i = 2; i < 512; i += 2){
		var new_point[2];
		new_point = add_point(powers[i-2], powers[i-1], powers[i-2], powers[i-1]);
		
		powers[i] = new_point[0];
		powers[i+1] = new_point[1];
	}

	for (var i = 0; i < 512; i += 2){
		if (r & 1){
			point = add_point(point[0], point[1], powers[i], powers[i+1]);
		}
		r >>= 1;
	}

	return point;
}

//Find min of a and b
function min(a, b) {
	return a * (a <= b) + b * (b < a);
}

//Add the bucket index to the date
function change_date(date, bucket, all_buckets, num_buckets) {
	var bucket_idx = 0;
	for (var i = 0; i < num_buckets; i++) {
		if (all_buckets[i] == bucket) {
			bucket_idx = i;
		}
	}
	return (date << 4) + bucket_idx;
}

//Slowly free up space for new passwords
function leak(dates, curr_date, num_dates) {
	var buckets_left = curr_date;
	var buckets_leaked = -1;
	var i = -1;

	while (buckets_left > 0) {
		i++;
		buckets_leaked++;
		buckets_left = min((curr_date >> 4) - (dates[i] >> 4), buckets_left - 1);
	}

	return buckets_leaked;
}

//Verify the previous state was signed
function Verify(hashed_msg, r, s_inv, new_nonce, old_nonce, protocol) {

	if (protocol == 0) {
		return (new_nonce == old_nonce);
	}
	
	else {
		var Ln = 251;
		var n = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
		
		var G[2];
		var pub[2];

		pub[0] = 11904445524001636151751598386728388840639132815445464908940192774200281587743;
		pub[1] = 7117856159918182929967406527153402219975952946948127235661172688414238266827;

		G[0] = 5299619240641551281634865583518297030282874472190772894086521144482721001553;
		G[1] = 16950150798460657717958625567821834550301663161624707787222815936182638968203;

		//Verify the ECDSA signature
		var z = hashed_msg >> 6;
		var u1 = mod_mult(z, s_inv, n);
		var u2 = mod_mult(r, s_inv, n);

		var p1[2];
		p1 = mult_point(G[0], G[1], u1);
		
		var p2[2];
		p2 = mult_point(pub[0], pub[1], u2);
		
		var point[2];
		point = add_point(p1[0], p1[1], p2[0], p2[1]);

		return (point[0] % n == r % n);
	}
}

//Multiply point by a scalar in BabyJubJub template
template BabyMult(N) {
    signal input r;
    signal input xin;
    signal input yin;
    signal output out[2];

    component rBits = Num2Bits(N);
    rBits.in <== r;

    component powers[N];

    powers[0] = BabyAdd();
    powers[0].x1 <== xin;
    powers[0].y1 <== yin;
    powers[0].x2 <== 0;
    powers[0].y2 <== 1;

    for (var i = 1; i < N; i++) {
        powers[i] = BabyAdd();
        powers[i].x1 <== powers[i-1].xout;
        powers[i].y1 <== powers[i-1].yout;
        powers[i].x2 <== powers[i-1].xout;
        powers[i].y2 <== powers[i-1].yout;
    }

    signal arr[2*N];
    component adding[N-1];

    arr[0] <== powers[0].xout * rBits.out[0];
    arr[1] <== powers[0].yout * rBits.out[0] + 1 - rBits.out[0];


    for (var i = 2; i < 2*N; i += 2) {
        adding[i\2-1] = BabyAdd();
        adding[i\2-1].x1 <== arr[i-2];
        adding[i\2-1].y1 <== arr[i-1];

        adding[i\2-1].x2 <== powers[i\2].xout * rBits.out[i\2];
        adding[i\2-1].y2 <== powers[i\2].yout * rBits.out[i\2] + 1 - rBits.out[i\2];

        arr[i] <== adding[i\2-1].xout;
        arr[i+1] <== adding[i\2-1].yout;
    }

    out[0] <== arr[2*N-2];
    out[1] <== arr[2*N-1];
}

//Convert an array of ints to array of bits
template ArrNum2Bits(n, k) {
	signal input in[n];
	signal output out[n * k];

	component bits[n];

	var out_var[n*k];

	for (var i = 0; i < n; i++) {
		bits[i] = Num2Bits(k);
		bits[i].in <== in[i];
		for (var j = 0; j < k; j++) {
			out_var[i*k + j] = bits[i].out[j];
		}
	}

	out <== out_var;


}

//Hash all of the inputs together using Sha256
template CreateStateHasher(num_buckets, num_total) { 
	
	signal input buckets[num_buckets];
	signal input object_counts[num_buckets];
	signal input dates[num_total];

	log(buckets[0]);
	log(buckets[1]);
	log(object_counts[0]);
	log(object_counts[1]);
	log(dates[0]);
	log(dates[1]);
	log(dates[2]);
	log(dates[3]);
	
	signal input serial;
	signal input password;

	log(serial);
	log(password);
	
	signal output out[256];

	var len = (64 + 4) * num_buckets + 24 * num_total + 64 + 64 + 1;
	var hash_in[len];
	
	component hasher = Sha256(len);

	component buckets_bits = ArrNum2Bits(num_buckets, 64);
	component objects_bits = ArrNum2Bits(num_buckets, 4);
	component dates_bits = ArrNum2Bits(num_total, 24);
	component serial_bits = Num2Bits(64);
	component password_bits = Num2Bits(64);

	buckets_bits.in <== buckets;
	objects_bits.in <== object_counts;
	dates_bits.in <== dates;
	serial_bits.in <== serial;
	password_bits.in <== password;

	for (var i = 0; i < num_buckets * 64; i++) {
		hash_in[i] = buckets_bits.out[i];
	}

	for (var i = 0; i < num_buckets * 4; i++) {
		hash_in[64 * num_buckets + i] = objects_bits.out[i];
	}

	for (var i = 0; i < num_total * 4; i++) {
		hash_in[(64 + 4) * num_buckets + i] = dates_bits.out[i];
	}

	for (var i = 0; i < 64; i++) {
		hash_in[(64 + 4) * num_buckets + 24 * num_total + i] = password_bits.out[i];
	}

	for (var i = 0; i < 64; i++) {
		hash_in[(64 + 4) * num_buckets + 24 * num_total + 64 + i] = serial_bits.out[i];
	}

	hasher.in <== hash_in;

	out <== hasher.out;

}

//Create the new state for output and old state for verification
template CreateStates(num_objects, num_buckets, num_total) {
	signal input new_bucket;
	signal input new_serial;
	signal input new_date;
	
	signal input protocol;
	
	signal input password;
	
	signal input old_buckets[num_buckets];	
	signal input old_object_counts[num_buckets];
	signal input old_serial;
	signal input old_dates[num_total];

	signal output old_state[256];
	signal output new_state[256];

	component old_hash = CreateStateHasher(num_buckets, num_total);
	component new_hash = CreateStateHasher(num_buckets, num_total);

	var new_buckets[num_buckets];
	var new_object_counts[num_buckets];
	var new_dates[num_total];

	old_hash.serial <== old_serial;
	old_hash.password <== password;
	old_hash.buckets <== old_buckets;
	old_hash.object_counts <== old_object_counts;
	old_hash.dates <== old_dates;

	old_state <== old_hash.out;

	component old_state_int = Bits2Num(256);
	old_state_int.in <== old_state;

	if (protocol == 0) {
		new_dates = old_dates;
		new_buckets = old_buckets;
		new_object_counts = old_object_counts;
	}

	else {
	
		var new_bucket_num = num_buckets;

		// Locate the index of new bucket if it is present or add if not
		for (var i = 0; i < num_buckets; i++) {

			new_buckets[i] = old_buckets[i];
			new_object_counts[i] = old_object_counts[i];

			if (old_buckets[i] == new_bucket && new_bucket != 0) {
				new_bucket_num = i;
				new_object_counts[i] = old_object_counts[i] + 1;
			}
			else if (new_bucket_num == num_buckets && old_buckets[i] == 0 && new_bucket != 0) {
				new_bucket_num = i;
				new_buckets[i] = new_bucket;
				new_object_counts[i] = old_object_counts[i] + 1;
			}
			
		}
		assert(new_bucket_num < num_buckets || new_bucket == 0);

		var new_date_var = change_date(new_date, new_bucket, new_buckets, num_buckets);

		if (new_bucket == 0) {
			new_date_var = new_date;
		}

		var buckets_leaked = leak(old_dates, new_date_var, num_total);

		//Leak the objects
		var new_date_added = 0;
		for (var i = 0; i < num_total; i++) {
			if (i < buckets_leaked) {
				if (old_dates[i] > 0){
					new_object_counts[old_dates[i] & 15] -= 1;
				}
			}
			
			if (num_total > i + buckets_leaked){
				new_dates[i] = old_dates[i + buckets_leaked];
			}
			else {
				new_dates[i] = 0;
			}
			
			if (new_dates[i] == 0 && new_date_added == 0) {
				new_dates[i] = new_date_var;
				new_date_added = 1;
			}

			if (new_object_counts[old_dates[i] & 15] == 0) {

				new_buckets[old_dates[i] & 15] = 0;
						
			}

		}

		//Make sure that the new date was added
		assert(new_date_added == 1);

		//Check object counts
		for (var i = 0; i < num_buckets; i++) {
			assert(new_object_counts[i] <= num_objects);
		}
	}

	new_hash.serial <== new_serial;
	new_hash.password <== password;
	new_hash.buckets <-- new_buckets;
	new_hash.object_counts <-- new_object_counts;
	new_hash.dates <-- new_dates;

	new_state <== new_hash.out;
}

//Generate the blinded unsigned key for encrypting the message
template oPRF(num_objects, num_buckets, num_total) { 

	//For verification
	signal input sig_r;
	signal input sig_s_inv;

	signal input password;
	signal input protocol;

	//New data
	signal input new_bucket;
	signal input new_object;
	signal input new_serial;
	signal input new_date;
	signal input new_nonce;

	
	//Old data
	signal input old_buckets[num_buckets];
	signal input old_object_counts[num_buckets];
	signal input old_serial;
	signal input old_dates[num_total];
	signal input old_nonce;

	//For blinding
	signal input r;

	
	signal output new_state;
	signal output ped_hash_r[2];

	component states = CreateStates(num_objects, num_buckets, num_total);
	states.new_bucket <== new_bucket;
	states.new_serial <== new_serial;
	states.new_date <== new_date;

	states.protocol <== protocol;
	states.password <== password;

	states.old_buckets <== old_buckets;
	states.old_object_counts <== old_object_counts;
	states.old_serial <== old_serial;
	states.old_dates <== old_dates;

	component hashed_msg_int = Bits2Num(256);
	hashed_msg_int.in <== states.old_state;


	if (sig_r != 0) {
		var verifier = Verify(hashed_msg_int.out, sig_r, sig_s_inv, new_nonce, old_nonce, protocol);
		assert(verifier == 1);
	}
	else {
		assert(new_bucket == 0);
		assert(new_object == 0);
		assert(new_serial == 0);
		assert(new_date == 0);
	}

	component new_state_int = Bits2Num(256);
	new_state_int.in <== states.new_state;

	new_state <== new_state_int.out;

	var ped_in[64 * 4];

	component password_bits = Num2Bits(64);
	password_bits.in <== password;

	component new_bucket_bits = Num2Bits(64);
	new_bucket_bits.in <== new_bucket;

	component new_object_bits = Num2Bits(64);
	new_object_bits.in <== new_object;

	component nonce_bits = Num2Bits(64);
	nonce_bits.in <== old_nonce;	

	for (var i = 0; i < 64; i++) {
		ped_in[i] = password_bits.out[i];
	}

	for (var i = 0; i < 64; i++) {
		ped_in[i + 64] = new_bucket_bits.out[i];
	}

	for (var i = 0; i < 64; i++) {
		ped_in[i + 64 * 2] = new_object_bits.out[i];
	}

	for (var i = 0; i < 64; i++) {
		ped_in[i + 64 * 3] = nonce_bits.out[i];
	}

	component ped = Pedersen(64 * 4);
	ped.in <== ped_in;

	component ped_r = BabyMult(256);
	ped_r.xin <== ped.out[0];
	ped_r.yin <== ped.out[1];
	ped_r.r <== r;

	ped_hash_r <== ped_r.out;

}

component main { public [ new_date, new_nonce, old_serial ] } = oPRF(2, 2, 4);