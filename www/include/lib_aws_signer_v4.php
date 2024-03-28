<?php

	# WORK IN PROGRESS. EVERYTHING WILL CHANGE.
	# Derived from https://github.com/avi-wish/aws4-signature-php

	# If you need to verify / sanity check things against a known-working implementation:
	# https://github.com/aaronland/go-aws-auth?tab=readme-ov-file#aws-sign-request
	
	function aws_signer_v4_headers($host, $uri, $requestUrl, $accessKey, $secretKey, $securityToken, $region, $service, $httpRequestMethod, $data, $debug = TRUE){

	$headers_to_sign = array(
		"content-length",
		"content-type",
		"host",
		"x-amz-date",
	);

	if ($securityToken != ""){
		$headers_to_sign[] = "x-amz-security-token";
	}
	
	$terminationString	= 'aws4_request';
	$algorithm 		= 'AWS4-HMAC-SHA256';
	$phpAlgorithm 		= 'sha256';
	$canonicalURI		= $uri;
	$canonicalQueryString	= '';
	$signedHeaders		= implode(";", $headers_to_sign);

	$currentDateTime = new DateTime('UTC');
	$reqDate = $currentDateTime->format('Ymd');
	$reqDateTime = $currentDateTime->format('Ymd\THis\Z');

	// Create signing key
	$kSecret = $secretKey;
	$kDate = hash_hmac($phpAlgorithm, $reqDate, "AWS4{$kSecret}", true);	
	$kRegion = hash_hmac($phpAlgorithm, $region, $kDate, true);
	$kService = hash_hmac($phpAlgorithm, $service, $kRegion, true);
	$kSigning = hash_hmac($phpAlgorithm, $terminationString, $kService, true);

	// Create canonical headers
	$canonicalHeaders = array();
	$canonicalHeaders[] = 'content-length:' . strlen($data);
	$canonicalHeaders[] = 'content-type:application/json';		
	$canonicalHeaders[] = 'host:' . $host;
	$canonicalHeaders[] = 'x-amz-date:' . $reqDateTime;

	if ($securityToken != ""){
		$canonicalHeaders[] = 'x-amz-security-token:' . $securityToken;
	}
	
	$canonicalHeadersStr = implode("\n", $canonicalHeaders);

	// Create request payload
	$requestHashedPayload = strtolower(bin2hex(hash($phpAlgorithm, $data, true)));

	// Create canonical request
	$canonicalRequest = array();
	$canonicalRequest[] = $httpRequestMethod;
	$canonicalRequest[] = $canonicalURI;
	$canonicalRequest[] = $canonicalQueryString;
	$canonicalRequest[] = $canonicalHeadersStr . "\n";
	$canonicalRequest[] = $signedHeaders;
	$canonicalRequest[] = $requestHashedPayload;
	$requestCanonicalRequest = implode("\n", $canonicalRequest);

	if ($debug){
		echo "[CANONICAL STRING]\n";
		echo "---\n";
		echo "{$requestCanonicalRequest}\n";
		echo "---\n";
	}

	$requestHashedCanonicalRequest = strtolower(bin2hex(hash($phpAlgorithm, $requestCanonicalRequest, true)));
	
	// Create scope
	$credentialScope = array();
	$credentialScope[] = $reqDate;
	$credentialScope[] = $region;
	$credentialScope[] = $service;
	$credentialScope[] = $terminationString;
	$credentialScopeStr = implode('/', $credentialScope);

	// Create string to signing
	$stringToSign = array();
	$stringToSign[] = $algorithm;
	$stringToSign[] = $reqDateTime;
	$stringToSign[] = $credentialScopeStr;
	$stringToSign[] = $requestHashedCanonicalRequest;
	$stringToSignStr = implode("\n", $stringToSign);
	
	if($debug){
		echo "[STRING TO SIGN]\n";
		echo "---\n";
		echo "{$stringToSignStr}\n";
		echo "---\n";
	}

	// Create signature
	
	$signature = hash_hmac($phpAlgorithm, $stringToSignStr, $kSigning);

	// Create authorization header
	$authorizationHeader = array();
	$authorizationHeader[] = 'Credential=' . $accessKey . '/' . $credentialScopeStr;
	$authorizationHeader[] = 'SignedHeaders=' . $signedHeaders;
	$authorizationHeader[] = 'Signature=' . ($signature);
	$authorizationHeaderStr = $algorithm . ' ' . implode(', ', $authorizationHeader);

	// Request headers
	$headers = array();
	$headers[] = 'accept:';
	$headers[] = 'authorization: '.$authorizationHeaderStr;
	$headers[] = 'content-length: '.strlen($data);
	$headers[] = 'content-type: application/json';
	$headers[] = 'host: ' . $host;
	$headers[] = 'x-amz-date: ' . $reqDateTime;

	if ($securityToken != ""){
		$headers[] = 'x-amz-security-token: ' . $securityToken;
	}
	
	return $headers;
}

/**
* This function is in use
* for send request with authorization header
*/
function callToAPI($requestUrl, $httpRequestMethod, $headers, $data, $debug=TRUE)
{

	// Execute the call
	$curl = curl_init();
	curl_setopt_array($curl, array(
	  CURLOPT_URL => $requestUrl,
	  CURLOPT_RETURNTRANSFER => true,
	  CURLOPT_FOLLOWLOCATION => true,
	  CURLOPT_TIMEOUT => 30,
	  CURLOPT_POST => true,
	  CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
	  CURLOPT_CUSTOMREQUEST => $httpRequestMethod,
	  CURLOPT_POSTFIELDS => $data,
	  CURLOPT_VERBOSE => 0,
	  CURLOPT_SSL_VERIFYHOST => 0,
	  CURLOPT_SSL_VERIFYPEER => 0,
	  CURLOPT_HEADER => false,
	  CURLINFO_HEADER_OUT=>true,
	  CURLOPT_HTTPHEADER => $headers,
	));

	$response = curl_exec($curl);
	$err = curl_error($curl);
	$responseCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);

	if($debug){
		$headers = curl_getinfo($curl, CURLINFO_HEADER_OUT);
		echo "[REQUEST]\n";
		echo "---\n";
		echo "{$headers}\n";
		echo "---\n";
	}

	curl_close($curl);

	if ($err) {
		if($debug){
			echo "<h5>Error:" . $responseCode . "</h5>";
			echo "<pre>";
			echo $err;
			echo "</pre>";
		}
	} else {
		if($debug){
			echo "<h5>Response:" . $responseCode . "</h5>";
			echo "<pre>";
			echo $response;
			echo "</pre>";
		}
	}
	
	return array(
		"responseCode" => $responseCode,
		"response" => $response,
		"error" => $err
	);
}// End callToAPI
