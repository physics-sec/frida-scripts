console.log("123456"[1:5]);

function get_pattern(number, isLittleEndian, bits, signed) {
	var hex_string = number.toString(16);
	var len = hex_string.length;
	if (len % 2 == 1) {
		hex_string = '0' + hex_string;
	}
	var rta = "";
	hex_string.match(/.{2}/g).forEach(function(byte) {
		if (isLittleEndian) {
			rta = byte + " " + rta;
		}
		else {
			rta = rta + " " + byte;
		}
	});
	if (isLittleEndian) {
		pattern = rta.substring(0, rta.length - 1);
	}
	else {
		pattern = rta.substr(1);
	}

	var lenPattern = pattern.split(" ").length;
	var bytesReg = Math.floor(bits/8);
	for (i = 0; i < (bytesReg - lenPattern); i++) {
		pattern = (isLittleEndian ? pattern + ' 00' : '00 ' + pattern);
	}
	var lenPattern = pattern.length;
	if (signed == "s" && number < 0) {
		if (isLittleEndian) {
			var prev = pattern.substring(lenPattern-1, lenPattern);
			var nvo = parseInt(prev);
			nvo |= 256;
			nvo = nvo.toString();
		}
		else {
			var prev = pattern.substring(0, 2);
			var nvo = parseInt(prev);
			nvo |= 256;
			nvo = nvo.toString();
		}
		pattern.replace(prev, nvo);
	}

	var byte_array = [];
	var bytes = pattern.split(" ");
	for (var i = bytes.length - 1; i >= 0; i--) {
		byte_array.push(parseInt("0x" + bytes[i]));
	}

	if (signed == "s" && number < 0) {
		if (isLittleEndian) {
			byte_array[bytesReg - 1] |= 256;
		}
		else {
			byte_array[0] |= 256;
		}
	}
	return byte_array;
}

function get_byte_array(number, isLittleEndian, bits, signed) {
	var pattern = get_pattern(number, isLittleEndian);
	var lenPattern = pattern.split(" ").length;
	var bytesReg = Math.floor(bits/8);
	for (i = 0; i < (bytesReg - lenPattern); i++) {
		pattern = (isLittleEndian ? pattern + ' 00' : '00 ' + pattern);
	}
	var byte_array = [];
	var bytes = pattern.split(" ");
	for (var i = bytes.length - 1; i >= 0; i--) {
		byte_array.push(parseInt("0x" + bytes[i]));
	}

	if (signed == "s" && number < 0) {
		if (isLittleEndian) {
			byte_array[bytesReg - 1] |= 256;
		}
		else {
			byte_array[0] |= 256;
		}
	}
	return byte_array;
}