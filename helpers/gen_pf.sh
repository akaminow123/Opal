#!/bin/bash

cd "$1"_js

node generate_witness.js "$1".wasm input.json witness.wtns

cd ..

snarkjs groth16 prove "$1"_0001.zkey "$1"_js/witness.wtns proof_"$1"_"$2".json public_"$1"_"$2".json
