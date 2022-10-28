# Threat Protection Java Callout

This directory contains the Java source code and Java jars required to
compile a Java callout for Apigee Edge that does regular expression pattern matching for threat protection.

The API Proxy subdirectory, which is a sibling to this one, includes the pre-built JAR file. Therefore you do not need to build this Java code in order to use the threat protector.

However, you may wish to modify this code for your own purposes. In that case, you will modify the Java code, re-build, then copy that JAR into the appropriate apiproxy/resources/java directory for the API Proxy.  

## Updates
### Release 6
Here is what happens when the Content-type header includes multipart/form-data.
1. Content-type header MUST have multipart/form-data. If this is not included then the entire payload will be included in the threat check.

2. If the Content-type header contains multipart/form-data, then it MUST include "boundary=...". If boundary= is not included then the entire payload is included in the threat check.

3. Request content MUST include a boundary; the boundary line tells servers how the payload should be parsed. If it doesn't include a boundary, then the threat protection will check all the content.  

4. The multipart content must
  a) include name="imagefile". If this is not found then it will not check for file types.  Threat protection will be performed on the entire payload. see the example below.

  sgovind1
  ------WebKitFormBoundary7MA4YWxkTrZu0gW
  Content-Disposition: form-data; name="imagefile"; filename="test.png"
  Content-Type: image/png

  fakebinarycontenthere.kj flsdjflsjfljslfdjsl
  ------WebKitFormBoundary7MA4YWxkTrZu0gW—

  b) The multipart content with the file must include: filename="filename.ext".  If filename is not included then the entire multipart will be included in the threat protection check.

5. Valid image types are ".jpg", ".png", ".jpeg", ".bmp", ".gif", ".tiff".  If a valid extension is not found then this multipart content will be included in the threat protection check.



Here is an example of valid payload:

Content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="imagecategory"

PROFILE
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="imagekeyname"

ntId
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="imagekeyvalue"

gsm1900\rgopina
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="uploaderid"

sgovind1
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="imagefile"; filename="test.png"
Content-Type: image/png

fakebinarycontenthere.kjflsdjflsjfljslfdjsl
------WebKitFormBoundary7MA4YWxkTrZu0gW—

### Release 5
An error was reported by T-mobile that certain images included in the payload would cause the threat protection policy to trigger and raise an error.  We have not identified the root cause yet.

However, I did test with the images and I can see that there are certain images that cause the threat protection to send an error.

I modified the callout so that it will skip the threat protection on the part of the payload that contains the binary content.
This will only happen if:
I. content-type header CONTAINS multipart/form-data (.i.e `Content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW`)

If the payload content-type header does not contain multipart/form-data then the callout will check the entire payload if one is included.  

NOTE the following:
1. The callout DOES NOT scan the content of the attached file.
2. The callout DOES NOT determine the content-type of the file.  
3. The callout relies on the file extension listed in the payload.
i.e.
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="imagefile"; filename="test.jpg"
Content-Type: image/jpeg

fakebinarycontenthere.kjflsdjflsjfljslfdjsl
------WebKitFormBoundary7MA4YWxkTrZu0gW—
```
4. if the following file extensions will cause the threat protection policy to skip checking the multiform part that has the binary content: `.jpg, .png, .jpeg, .bmp, .gif, .tiff`


### Release 4
1. BUG: the previous release was using an instance variable `isThreatDetected`; however this variable was not reset once the callout completed executing. Changed `isThreatDetected` to a local variable in the `execute` method.

2. The previous callout required the developer to check a flow variable to determine if a threat was detected.  This could result in a developer failing to check this variable or checking the wrong thing and this would allow requests with threats to go through to the target server.  Changed the callout so it raises an error when a threat is detected.  The message is:
```
500 Internal Server Error
{"fault":
  {
    "detail":{ "errorcode":"ThreatCallout" },
    "faultstring":"Threat detected."
  }
}
```

3. Renamed the package to `com.tmobile.security.threatcheck` and `com.tmobile.security.threatcheck.utils`.

### Release 3
1. `matchQueryParams` and `matchHeaders` are both required properties. If they are
not specified then an IllegalStateException is raised and the policy results in an error.

2. If `matchQueryParams` or `matchHeaders` contains an invalid value (i.e. blank, misspelled),
then an IllegalStateException is raised and the policy results in an error.

3. If the policy is misconfigured](#misconfiguredPolicy), then the `threat_warnings` variable is populated with a warning.  What does misconfigured mean? It means that if a threat includes a pattern, but that pattern is not defined, then a flow variable named `threat_warnings` is populated with a message like `pattern_15 is not specified or is empty.|`.

4. Payload content is no longer required. This allows you to execute this policy in a GET flow.

5. Query parameters are checked if:
  * there are query parameters and
  * the `matchQueryParams` is set with true

6. headers are checked if:
  * there are headers and
  * the `matchHeaders` is set with true

7. Request payload (`request.content`) is checked if there is a payload included in the request.  The payload is checked even if the `toMatch` parameter is NOT set.

8. If the `toMatch` parameter is set, then that variable will be checked for threats.

9. If the `toMatch` parameter is set, but it resolves to a blank or null result, then the `request.content` (payload) will be checked instead, provided that a payload is included on the request.


### Prior Releases
1. If you misconfigure the policy then it ignores the error and continues with the other threats.
2. Payload content is required.
3. If the `toMatch` property is MISSING, then it WILL NOT check the payload

## Summary
The policy will fail fast, so
* If it detects a threat in the query parameters, then it will not check for threats in the headers or payload.  
* If there are no headers/query parameters, then it will not check for threats there.
* If the `toMatch` property is set, then it will check for threats in the variable included in that property.
* If the `toMatch` property is set, but it evaluates to null or blank, then it will check the `request.content` variable instead.
* If the `toMatch` property is missing, then it will check for threats in the `request.content variable`, provided that there is a payload on the request.
* If the payload is empty, then it will not check for threats there.


### Threat Pattern
A threat pattern or "pattern" is a regular expression used to evaluate a
header, query param or payload content.
i.e.
```

```

### Order of Threat Evaluation
The policy checks for threats in the following order:
1. query parameters
2. headers
3. payload

### Threat Categories
There are currently 4 threats (see sample callout below):
1. threat_js - should include patterns that check for JavaScript threats
2. threat_sql - should include patterns that check for SQL injection threats
3. threat_xpath - should include patterns that check for xpath threats
4. threat_server - should include patterns that check for server side threats

The reason the patterns are separated into threat categories (called "threats")
is because this Java Callout will execute each "threat" in a separate thread.
Assume that the properties below are set in the Java Callout.  This callout will create
4 threads, one for each threat. Then it will wait for the 4 threads to complete
and check if a threat was found and if a threat was found then it exits and it populates
flow variables with the results.

```
<Property name="matchQueryParams">true</Property>
<Property name="matchHeaders">true</Property>
<Property name="match">{request.content}</Property>
```

* First it will check the query parameters, since matchQueryParams is true.
  It will create 4 threads for the the 4 threat categories and all the threads will
  check the query parameters for threats. The thread stops executing once it detects
  a threat.
* Next it will check the headers if a threat was not found in the query parameters.  It will create 4 threads
  for the the 4 threat categories and all the threads will check the headers for threats.
  The thread stops executing once it detects a threat.
* Next it will check the payload if a threat was not found in the headers.  It will create 4 threads
  for the the 4 threat categories and all the threads will check the payload for threats.
  The thread stops executing once it detects a threat.


### Flow Variables Created by this Callout

#### On Success
If the policy executes successfully, then the following flow variables are set.

1. `detectedThreats` - This variable tells you what threat(s) were detected.
  The following is a list of threats detected in the payload.
  * threat_js_
  * threat_sql_
  * threat_xpath_
  * threat_server_

    When a threat is detected in the header then `detectedThreats` will display the following.
    * threat_js_header-name_
    * threat_sql_header-name_
    * threat_xpath_header-name_
    * threat_server_header-name_

    i.e. If a threat is detected in Content-Type header then you would see `threat_js_Content-Type_`

    When a threat is detected in the query parameter then `detectedThreats` will display the following.
    * threat_js_queryparam_
    * threat_sql_queryparam_
    * threat_xpath_queryparam_
    * threat_server_queryparam_

    If more than one threat is detected for query parameter then it will concatenate
    all the threats in `detectedThreatS`.

    i.e. `threat_js_Content-Type_threat_server_Authorization_`


2. For each threat you can access the matched Regex pattern from the
  `detectedThreats` flow variable.  
   Assume `threat_js_Content-Type_threat_server_Authorization_` is in `detectedThreats`, then
   you could access the Regex patterns with `threat_js_Content-Type_matched` and `threat_server_Authorization_matched`.


#### On Failure
If an error occurs, then the following flow variables are created.
1. threat_error - the error class and the message.
2. threat_reason - the error message.
3. threat_stacktrace - the stack trace that lead to the error.
4. detectedThreats is null

### Required Properties
The following properties are required.  If they are not included then the policy will ABORT
and return an error during runtime.  

```
<Property name="matchQueryParams">true</Property>
<Property name="matchHeaders">true</Property>
```
#### Valid Values for matchQueryParams and matchHeaders
The only valid values are `true` or `false`; anything else will cause an error during runtime.

### Configuring the Callout Policy:

See example below:

```xml
  <JavaCallout name='Java.ThreatProtect'>
  <Properties>
    <!-- JS injection patterns -->
    
    <Property name="pattern_2">n\s*\\\\\s*slash</Property>
    <Property name="pattern_3">n\s*\/\s*slash</Property>
    <Property name="pattern_4">n\s*\\"\s*quotes</Property>
    <Property name="pattern_5">n\s*\\b\s*space</Property>
    <Property name="pattern_6">n\s*\\f\s*forwardfeed</Property>
    <Property name="pattern_7">n\s*\\n\s*newline</Property>
    <Property name="pattern_8">n\s*\\r\s*carria</Property>
    <Property name="pattern_9">n\s*\\t\s*tab</Property>
    <Property name="pattern_10">n\s*\\uFFFF\s*hex</Property>

    <!-- sql injection patterns -->
    <Property name="pattern_11">(?i)\b(alter|create|delete|(drop\s*table)|(truncate\s*table)|exec(ute)?|(insert\s*into)|merge|select|update|union( +all)?)\b</Property>
    <Property name="pattern_12">(?i)\b\d+\b\s*;\s*(\b(alter|create|delete|(drop\s*table)|(truncate\s*table)|exec(ute)?|(insert\s*into)|merge|select|update|union( +all)?)\b)\s*\w+</Property>
    <Property name="pattern_13">(?i)"\s*\bor\b\s*"\s*"="</Property>

    <!-- xpath injection patterns -->
    <Property name="pattern_14">(?i)\b(ancestor|ancestor-or-self|attribute|child|descendant|descendant-or-self|following|following-sibling|namespace|parent|preceding|preceding-sibling|self)\b[\s]*::.*=</Property>
    <Property name="pattern_15">(?i)(/([\w]+))(.*\b(or)\b)(.*(\=))</Property>

    <!-- server side include patterns -->
    <Property name="pattern_16">(?i)(&lt;!--\s*#\s*(include|exec|echo|config|printenv|fsize).*-->)</Property>

    <!-- threats -->
    <Property name="threat_js">pattern_1,pattern_2,pattern_3,pattern_4,pattern_5,pattern_6,pattern_7,pattern_8,pattern_9,pattern_10</Property>
    <Property name="threat_sql">pattern_11,pattern_12,pattern_13</Property>
    <Property name="threat_xpath">pattern_14,pattern_15</Property>
    <Property name="threat_serverside">pattern_16</Property>
    <Property name="matchQueryParams">true</Property>
    <Property name="matchHeaders">true</Property>
    <Property name="match">{request.content}</Property>
  </Properties>

  <ClassName>com.apigee.callout.threats.ThreatCallout</ClassName>
  <ResourceURL>java://threat-callout.jar</ResourceURL>
</JavaCallout>
```

This xml contains a bunch of regular expression patterns, that are grouped into individual threats. Each threat is then executed in its own thread within the callout, applying its grouped patterns. Once a pattern is matched, the java callout emits a context variable for each threat that matched its' pattern.

It emits the dot-separated threat pattern into the variable named
    threat\_<threat>\_matched = <pattern>

where
  <threat> is the name of the threat property defined in the java callout xml
  <pattern> is the regular expression pattern  defined for this threat that matched the input


### Proxy Verification

Using the above context variables in the proxy flow, you can add conditional logic to throw a fault or send a response back to the client.

### Misconfigured Policy <a name="misconfiguredPolicy"></a>
* <a name="misconfiguredPolicy1">Callout includes a pattern, but that pattern is not included in a "threat".</a>  Notice below that there are 3 patterns defined, 11, 12 and 13.  However, notice that the threat "threat_sql" only includes patterns 11 and 13. In this instance, the callout will ignore pattern 12 and that pattern will NOT be checked. The flow variable `threat_warnings` WILL NOT be populated.
  ```
  <Property name="pattern_11">(?i)';\b(alter|create|delete|(drop\s*table)|(truncate\s*table)|exec(ute)?|(insert\s*into)|merge|select|update|union( +all)?)\b</Property>
  <Property name="pattern_12">(?i)\b\d+\b\s*;\s*(\b(alter|create|delete|(drop\s*table)|(truncate\s*table)|exec(ute)?|(insert\s*into)|merge|select|update|union( +all)?)\b)\s*\w+</Property>
  <Property name="pattern_13">(?i)"\s*\bor\b\s*"\s*"="</Property>

  <Property name="threat_sql">pattern_11,pattern_13</Property>
  ```


* Callout includes a pattern in the threat, but that pattern is not included in the policy
  Notice that there are two patterns defined, 11 and 12; however, in the "threat_sql" also includes pattern 13. In this instance, the callout will ignore pattern 13 and continue checking the other threats.  The flow variable `threat_warnings` will be populated. (i.e. `pattern_13 is not specified or is empty.|`)
  ```
  <Property name="pattern_11">(?i)';\b(alter|create|delete|(drop\s*table)|(truncate\s*table)|exec(ute)?|(insert\s*into)|merge|select|update|union( +all)?)\b</Property>
  <Property name="pattern_12">(?i)\b\d+\b\s*;\s*(\b(alter|create|delete|(drop\s*table)|(truncate\s*table)|exec(ute)?|(insert\s*into)|merge|select|update|union( +all)?)\b)\s*\w+</Property>

  <Property name="threat_sql">pattern_11,pattern_12,pattern_13</Property>
  ```

## Using the Jar

You do not need to build the JAR in order to use it. The jar is located in
`apiproxy/resources/java` directory.
To use it:

1. Include the Java callout policy in your
   apiproxy/policies directory. The configuration should look like
   this:
    ```xml
    <JavaCallout name='Java.ThreatProtect'>
      <Properties>
        ...
      </Properties>
      <ClassName>com.apigee.callout.threats.ThreatCallout</ClassName>
      <ResourceURL>java://threat-callout.jar</ResourceURL>
</JavaCallout>
   ```

2. Deploy your API Proxy

For some examples of how to configure the callout, see the related api proxy bundle.


## Dependencies

Jars available in Edge:   
 - Apigee Edge expressions v1.0
 - Apigee Edge message-flow v1.0

### How do I get the dependencies?

Unfortunately, these jar files are not in the Maven central repository.  However, they are included in the `lib` directory.  You must install these into your local maven repository by following the steps below.  Once you install these jar files they you can run `mvn package` or `mvn test` to run the TestNG test scripts.

1. `cd lib`
2. Execute the following maven command to install the expressions-1.0.0.jar file.
```
mvn install:install-file \
 -Dfile=expressions-1.0.0.jar \
 -DgroupId=com.apigee.edge \
 -DartifactId=expressions \
 -Dversion=1.0.0 \
 -Dpackaging=jar \
 -DgeneratePom=true
```

3. Execute the following maven command to install the message-flow-1.0.0.jar file.
```
mvn install:install-file \
 -Dfile=message-flow-1.0.0.jar \
 -DgroupId=com.apigee.edge \
 -DartifactId=message-flow \
 -Dversion=1.0.0 \
 -Dpackaging=jar \
 -DgeneratePom=true
```


You can also download the dependencies here.
https://github.com/apigee/api-platform-samples/tree/master/doc-samples/java-cookbook/lib


## Building the Jar

To build the binary JAR yourself, follow
these instructions.

1. cd to the `callout` directory.

2. Build the binary with [Apache maven](https://maven.apache.org/). You need to first install it, and then you can execute the following line in your terminal:  
   ```
   mvn clean package
   ```

3. Maven will copy all the required jar files to the `apiproxy/resources/java` directory.
   The `threat-callout.jar` file will also be located in the `callout/src/target/` directory.


## Skip Tests
If you don't want to execute the tests then execute the following line. However,
if you change the source code you should execute the tests to make you didn't
break the existing functionality.
```
mvn package -DskipTests
```

## Execute TestNG tests
```
mvn test
```

## Deploy the Sample Threat Protection Proxy To Edge
There are two ways to deploy this proxy to Edge.


### Preferred Deployment Method
This method will build the threat-callout.jar, execute the TestNG tests, copy the jar to the `apiproxy/resources/java` directory, deploy the proxy to Edge, and execute the apickli/cucumber tests.

1. cd to the `RI-threat-protection` directory

2. Execute the following maven command.  This will build the threat-callout.jar file and copy it into    the `apiproxy/resources/java` directory.  It will execute the TestNG tests and then deploy the proxy to your org.  
  ```
  mvn install -Penv -Dusername=orgadmin@email.com -Dpassword=orgadminpwd -Dorg=orgname
  ```


### Alternative Deployment Method
NOTE: this will not build the jar file or execute the TestNG tests.  Therefore, you must build the jar first, then execute the steps below.  

1. cd to the `bin` directory

2. Update the the following variables in the `setenv.sh` file.
```
org="orgname"
username="apigee_org_admin_email"
url="https://api.enterprise.apigee.com"
env="environment"
api_domain="apigee.net"
```

3. Execute
```
./deploy.sh
```

4. Enter your Apigee org admin password when prompted. This will deploy the Sample Threat Protection proxy to your org.

5. Invoke a sample test.
```
./invoke.sh
```

## Execute the Apickli/Cucumber Tests only
If you only want to execute the Apickli/Cucumber tests then execute the following command.

```
cd RI-threat-protection

./test.sh orgname env
```

## Execute the Apickli/Cucumber Test only
TODO - This section is not complete.  
If the above command does not work then execute the following commands:


```
cucumber-js test/integration/threat-callout-api.feature
```
OR

```
cucumber test/integration/threat-callout-api.feature --format html > features.html
```
