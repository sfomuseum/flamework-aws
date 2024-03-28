<?php

	# This was originally derived from https://github.com/avi-wish/aws4-signature-php

	# If you need to verify / sanity check things against a known-working implementation:
	# https://github.com/aaronland/go-aws-auth?tab=readme-ov-file#aws-sign-request

	function aws_signer_v4_execute_request($http_method, $uri, $region, $service, $creds, $data){

		$headers = aws_signer_v4_headers($http_method, $uri, $region, $service, $creds, $data);

		// START OF for reasons I do not understand
		// there is something about using the lib_http methods (below) that makes AWS sad
		// and return "403 Forbidden" errors. For the sake of expediency we are just going
		// to call the native curl functions until I can figure out what is going on.
		
		$ch = curl_init();
		
		curl_setopt_array($ch, array(
			CURLOPT_URL => $uri,
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_FOLLOWLOCATION => true,
			CURLOPT_TIMEOUT => 30,
			CURLOPT_POST => true,
			CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
			CURLOPT_CUSTOMREQUEST => $http_method,
			CURLOPT_POSTFIELDS => $data,
			CURLOPT_VERBOSE => 0,
			CURLOPT_SSL_VERIFYHOST => 1,
			CURLOPT_SSL_VERIFYPEER => 1,
			CURLOPT_HEADER => false,
			CURLINFO_HEADER_OUT=>true,
			CURLOPT_HTTPHEADER => $headers,
		));

		$rsp = curl_exec($ch);		
		$rsp_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

		curl_close($ch);
		
		if (($rsp_code >= 200) && ($rsp_code <= 299)){
			return array("ok" => 1, "body" => $rsp);
		}

		$err = curl_error($ch);

		if ($err != ""){
			$rsp = $err;
		}
		
		return array("ok" => 0, "error" => $rsp);

		// END OF for reasons I do not understand
		
		/*	
		switch (strtoupper($http_method)){
		case "GET":
			return http_get($uri, $headers);
			break;
		case "POST":
			return http_post($uri, $data, $headers);
			break;
		case "PUT":
			return http_put($uri, $data, $headers);
			break;
		case "PUT":
			return http_put($uri, $data, $headers);
			break;
		default:
			return array("ok" => 0, "error" => "Unsupported method");
			break;
		}
		*/
	}

	function aws_signer_v4_headers($http_method, $uri, $region, $service, $creds, $data, $debug=FALSE){

		$host = parse_url($uri, PHP_URL_HOST);
		$path = parse_url($uri, PHP_URL_PATH);
		$query = parse_url($uri, PHP_URL_QUERY);

		$access_key = $creds["access_key"];
		$secret_key = $creds["secret_key"];
		$security_token = $creds["security_token"];
		
		$headers_to_sign = array(
			"content-length",
			"content-type",
			"host",
			"x-amz-date",
		);

		if ($security_token != ""){
			$headers_to_sign[] = "x-amz-security-token";
		}
	
		$termination_string	= 'aws4_request';
		$algorithm 		= 'AWS4-HMAC-SHA256';
		$php_algorithm 		= 'sha256';
		$canonical_uri		= $path;	// $uri;
		$canonical_query_string	= $query;	// '';
		$signed_headers		= implode(";", $headers_to_sign);

		$dt = new DateTime('UTC');
		$req_date = $dt->format('Ymd');
		$req_datetime = $dt->format('Ymd\THis\Z');
		
		// Create signing key
		$k_secret = $secret_key;
		$k_date = hash_hmac($php_algorithm, $req_date, "AWS4{$k_secret}", true);	
		$k_region = hash_hmac($php_algorithm, $region, $k_date, true);
		$k_service = hash_hmac($php_algorithm, $service, $k_region, true);
		$k_signing = hash_hmac($php_algorithm, $termination_string, $k_service, true);

		// Create canonical headers
		$canonical_headers = array();
		$canonical_headers[] = 'content-length:' . strlen($data);
		$canonical_headers[] = 'content-type:application/json';		
		$canonical_headers[] = 'host:' . $host;
		$canonical_headers[] = 'x-amz-date:' . $req_datetime;

		if ($security_token != ""){
			$canonical_headers[] = 'x-amz-security-token:' . $security_token;
		}
	
		$canonical_headers_str = implode("\n", $canonical_headers);

		// Create request payload
		$req_payload_hashed = strtolower(bin2hex(hash($php_algorithm, $data, true)));

		// Create canonical request
		$canonical_request = array();
		$canonical_request[] = $http_method;
		$canonical_request[] = $canonical_uri;
		$canonical_request[] = $canonical_query_string;
		$canonical_request[] = $canonical_headers_str . "\n";
		$canonical_request[] = $signed_headers;
		$canonical_request[] = $req_payload_hashed;
		$canonical_request_str = implode("\n", $canonical_request);

		if ($debug){
			echo "[CANONICAL STRING]\n";
			echo "---\n";
			echo "{$canonical_request_str}\n";
			echo "---\n";
		}

		$canonical_request_hashed = strtolower(bin2hex(hash($php_algorithm, $canonical_request_str, true)));

		// Create scope
		$credential_scope = array();
		$credential_scope[] = $req_date;
		$credential_scope[] = $region;
		$credential_scope[] = $service;
		$credential_scope[] = $termination_string;
		$credential_scope_str = implode('/', $credential_scope);

		// Create string to signing
		$to_sign = array();
		$to_sign[] = $algorithm;
		$to_sign[] = $req_datetime;
		$to_sign[] = $credential_scope_str;
		$to_sign[] = $canonical_request_hashed;
		$to_sign_str = implode("\n", $to_sign);
	
		if ($debug){
			echo "[STRING TO SIGN]\n";
			echo "---\n";
			echo "{$to_sign_str}\n";
			echo "---\n";
		}

		// Create signature
	
		$signature = hash_hmac($php_algorithm, $to_sign_str, $k_signing);

		// Create authorization header
		$auth_header = array();
		$auth_header[] = 'Credential=' . $access_key . '/' . $credential_scope_str;
		$auth_header[] = 'SignedHeaders=' . $signed_headers;
		$auth_header[] = 'Signature=' . ($signature);
		$auth_header_str = $algorithm . ' ' . implode(', ', $auth_header);

		// Request headers
		$headers = array();
		$headers[] = 'accept:';
		$headers[] = 'authorization: '.$auth_header_str;
		$headers[] = 'content-length: '.strlen($data);
		$headers[] = 'content-type: application/json';
		$headers[] = 'host: ' . $host;
		$headers[] = 'x-amz-date: ' . $req_datetime;

		if ($security_token != ""){
			$headers[] = 'x-amz-security-token: ' . $security_token;
		}
	
		return $headers;
}