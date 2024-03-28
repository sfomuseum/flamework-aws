# flamework-aws

Limited (and opionated) methods for working with AWS services in a Flamework-based application.

## Documentation

### lib_aws_signer_v4.php

#### aws_signer_v4_headers($http_method, $uri, $region, $service, $creds, $data, $debug=FALSE)

Return an array containing the necessary header for executing an AWS "v4" signed request. For example:

```
$http_method = "POST";
$uri = "https://{SOME_FUNCTION_URL}.lambda-url.{REGION}.on.aws/api/point-in-polygon";
$region = "{REGION}";
$service = "lambda";

// How and where these AWS credentials are derived is left to be determined on a per-application basis.
$creds = array(
	"access_key" => "...",
	"secret_key" => "...",
	"security_token" => "...",
);

$data = json_encode(array("latitude" => 25.0, "longitude" => -45.6 ));

$headers = aws_signer_v4_headers($http_method, $uri, $region, $service, $creds, $data);
dumper($headers);
```

#### aws_signer_v4_execute_request($http_method, $uri, $region, $service, $creds, $data)

Execute an AWS "v4" signed request and return the result. For example:

```
$http_method = "POST";
$uri = "https://{SOME_FUNCTION_URL}.lambda-url.{REGION}.on.aws/api/point-in-polygon";
$region = "{REGION}";
$service = "lambda";

// How and where these AWS credentials are derived is left to be determined on a per-application basis.
$creds = array(
	"access_key" => "...",
	"secret_key" => "...",
	"security_token" => "...",
);

$data = json_encode(array("latitude" => 25.0, "longitude" => -45.6 ));

$rsp = aws_signer_v4_execute_request($http_method, $uri, $region, $service, $creds, $data);
dumper($rsp);
```

Which, in this example, would return something like:

```
array (
  'ok' => 1,
  'body' => '{"places":[{"wof:id":"404528709","wof:parent_id":"-1","wof:name":"North Atlantic Ocean","wof:country":"","wof:placetype":"ocean","mz:latitude":0,"mz:longitude":0,"mz:min_latitude":24.965357,"mz:min_longitude":0,"mz:max_latitude":-45.616087,"mz:max_longitude":-45.570425,"mz:is_current":1,"mz:is_deprecated":-1,"mz:is_ceased":-1,"mz:is_superseded":0,"mz:is_superseding":0,"edtf:inception":"","edtf:cessation":"","wof:supersedes":[],"wof:superseded_by":[],"wof:belongsto":[],"wof:path":"404/528/709/404528709.geojson","wof:repo":"whosonfirst-data-admin-xy","wof:lastmodified":1690923898}]}
',
)
```

## See also

* https://github.com/sfomuseum/flamework