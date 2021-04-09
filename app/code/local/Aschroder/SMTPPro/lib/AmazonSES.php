<?php
// @codingStandardsIgnoreFile

/**
 * Zend_Http_Client extended for a function to sign a request for AmazonSES with signature version 4.
 *
 * @author jEzEk - 20210222
 */
class Zend_Http_Client_AmazonSES_SV4 extends Zend_Http_Client
{

    const HASH_ALGORITHM = 'sha256';
    public static $SESAlgorithms = [
        self::HASH_ALGORITHM => 'AWS4-HMAC-SHA256',
    ];

    /**
     * Returns header string containing encoded authentication key needed for signature version 4 as described in https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
     *
     * @param DateTime $date
     * @param string $region
     * @param string $service
     * @param string $accessKey
     * @param string $privateKey
     * @return  string
     *
     */
    public function buildAuthKey(DateTime $date, $region, $service, $accessKey, $privateKey)
    {
        //Mage::log(__METHOD__);
        $longDate = $date->format('Ymd\THis\Z');
        $shortDate = $date->format('Ymd');

        // Add minimal headers
        $this->setHeaders([
            'Host' => $this->uri->getHost(),
            'X-Amz-Date' => $longDate,
        ]);

        // Task 1: Create a canonical request for Signature Version 4
        // 1. Start with the HTTP request method (GET, PUT, POST, etc.), followed by a newline character.
        $method = $this->method . "\n";

        // 2. Add the canonical URI parameter, followed by a newline character
        $canonicalUri = $this->pathEncode($this->uri->getPath()) . "\n";

        // 3. Add the canonical query string, followed by a newline character.
        $canonicalQuery = $this->getQuery() . "\n";

        // 4. Add the canonical headers, followed by a newline character.
        $canonicalHeaders = "";
        $headers = $this->headers;
        ksort($headers, SORT_STRING);
        foreach ($headers as $k => $v) {
            $canonicalHeaders .= $k . ':' . $this->trimAllSpaces($v[1]) . "\n";
        }
        $canonicalHeaders .= "\n";

        // 5. Add the signed headers, followed by a newline character.
        $signedHeaders = implode(';', array_keys($headers)) . "\n";

        // 6. Use a hash (digest) function like SHA256 to create a hashed value from the payload in the body of the HTTP or HTTPS request.
        $hashedPayload = $this->hash($this->_prepareBody());

        // 7. To construct the finished canonical request, combine all the components from each step as a single string.
        $canonicalRequest = $method . $canonicalUri . $canonicalQuery . $canonicalHeaders . $signedHeaders . $hashedPayload;

        //Mage::log('canonicalRequest:');
        //Mage::log("#####\n" . $canonicalRequest . "\n#####");

        // 8. Create a digest (hash) of the canonical request with the same algorithm that you used to hash the payload.
        $hashedCanonicalRequest = $this->hash($canonicalRequest);

        // Task 2:
        // 1. Start with the algorithm designation, followed by a newline character.
        $algorithm = self::$SESAlgorithms[self::HASH_ALGORITHM] . "\n";

        // 2. Append the request date value, followed by a newline character.
        $requestDateTime = $longDate . "\n";

        // 3. Append the credential scope value, followed by a newline character.
        $credentialScope = $shortDate . '/' . $region . '/' . $service . '/aws4_request' . "\n";

        // 4. Append the hash of the canonical request that you created in Task 1: Create a canonical request for Signature Version 4.
        $stringToSign = $algorithm . $requestDateTime . $credentialScope . $hashedCanonicalRequest;

        //Mage::log('stringToSign:');
        //Mage::log("#####\n" . $stringToSign . "\n#####");

        // Task 3: Calculate the signature for AWS Signature Version 4
        // 1. Derive your signing key.
        $dateKey = hash_hmac(self::HASH_ALGORITHM, $shortDate, 'AWS4' . $privateKey, true);
        $regionKey = hash_hmac(self::HASH_ALGORITHM, $region, $dateKey, true);
        $serviceKey = hash_hmac(self::HASH_ALGORITHM, $service, $regionKey, true);
        $signingKey = hash_hmac(self::HASH_ALGORITHM, 'aws4_request', $serviceKey, true);

        // 2. Calculate the signature.
        $signature = hash_hmac(self::HASH_ALGORITHM, $stringToSign, $signingKey);

        // Task 4: Add the signature to the HTTP request
        // Return string for HTTP Authorization header
        return trim($algorithm, "\n") . ' Credential=' . $accessKey . '/' . trim($credentialScope, "\n") . ', SignedHeaders=' . trim($signedHeaders, "\n") . ', Signature=' . $signature;
    }

    protected function pathEncode($path)
    {
        $encoded = [];
        foreach (explode('/', $path) as $k => $v) {
            $encoded[] = rawurlencode(rawurlencode($v));
        }
        return implode('/', $encoded);
    }

    protected function trimAllSpaces($text)
    {
        return trim(preg_replace('| +|', ' ', $text), ' ');
    }

    protected function hash($text)
    {
        return hash(self::HASH_ALGORITHM, $text);
    }

    protected function getQuery()
    {
        // From Zend_Http_Client:L946
        // Clone the URI and add the additional GET parameters to it
        $uri = clone $this->uri;
        if (!empty($this->paramsGet)) {
            $query = $uri->getQuery();
            if (!empty($query)) {
                $query .= '&';
            }
            $query .= http_build_query($this->paramsGet, null, '&');
            if ($this->config['rfc3986_strict']) {
                $query = str_replace('+', '%20', $query);
            }

            $uri->setQuery($query);
        }
        return $uri->getQuery();
    }
}

/**
 * Amazon Simple Email Service (SES) connection object
 *
 * Integration between Zend Framework and Amazon Simple Email Service
 *
 * @category    Zend
 * @package     Zend_Mail
 * @subpackage  Transport
 * @author      Christopher Valles <info@christophervalles.com>
 * @license     http://framework.zend.com/license/new-bsd New BSD License
 */
class App_Mail_Transport_AmazonSES extends Zend_Mail_Transport_Abstract
{
    /**
     * Template of the webservice body request
     *
     * @var string
     */
    protected $_bodyRequestTemplate = 'Action=SendRawEmail&Source=%s&%s&RawMessage.Data=%s';


    /**
     * Remote smtp hostname or i.p.
     *
     * @var string
     */
    protected $_host;


    /**
     * Amazon Access Key
     *
     * @var string|null
     */
    protected $_accessKey;


    /**
     * Amazon private key
     *
     * @var string|null
     */
    protected $_privateKey;

    /**
     * Amazon region endpoint
     *
     * @var string|null
     */
    protected $_region;

    private $endpoints = array(
        'US-EAST-1' => 'https://email.us-east-1.amazonaws.com',
        'US-WEST-2' => 'https://email.us-west-2.amazonaws.com',
        'EU-WEST-1' => 'https://email.eu-west-1.amazonaws.com',
        'EU-CENTRAL-1' => 'https://email.eu-central-1.amazonaws.com',
    );


    /**
     * Constructor.
     *
     * @param array|null $config (Default: null)
     * @param string $host (Default: https://email.us-east-1.amazonaws.com)
     * @return void
     * @throws Zend_Mail_Transport_Exception if accessKey is not present in the config
     * @throws Zend_Mail_Transport_Exception if privateKey is not present in the config
     */
    public function __construct(array $config = array(), $region = 'https://email.us-east-1.amazonaws.com')
    {
        if (!array_key_exists('accessKey', $config)) {
            throw new Zend_Mail_Transport_Exception('This transport requires the Amazon access key');
        }

        if (!array_key_exists('privateKey', $config)) {
            throw new Zend_Mail_Transport_Exception('This transport requires the Amazon private key');
        }

        $this->_accessKey = $config['accessKey'];
        $this->_privateKey = $config['privateKey'];
        $regionKey = array_search($region, $this->endpoints);
        if (!$regionKey) {
            throw new InvalidArgumentException('Invalid Regionkey');
        }
        $this->_region = $regionKey;
        $this->setRegion($region);
    }

    public function setRegion($region)
    {
        if (!isset($region)) {
            throw new InvalidArgumentException('Region unrecognised');
        }
        return $this->_host = Zend_Uri::factory($region);
    }

    /**
     * Send an email using the amazon webservice api
     *
     * @return void
     */
    public function _sendMail()
    {
        //Build the parameters
        $params = array(
            'Action' => 'SendRawEmail',
            'Source' => $this->_mail->getFrom(),
            'RawMessage.Data' => base64_encode(sprintf("%s\n%s\n", $this->header, $this->body))
        );
        $recipients = explode(',', $this->recipients);
        while (list($index, $recipient) = each($recipients)) {
            $params[sprintf('Destinations.member.%d', $index + 1)] = $recipient;
        }

        // Create client
        $client = new Zend_Http_Client_AmazonSES_SV4($this->_host);
        $client->setMethod(Zend_Http_Client::POST);
        $client->setParameterPost($params);

        // Add authorization header
        $client->setHeaders(array(
            'Authorization' => $client->buildAuthKey(new DateTime('NOW'), strtolower($this->_region), 'email', $this->_accessKey, $this->_privateKey)
        ));

        // Send request
        $response = $client->request(Zend_Http_Client::POST);

        if ($response->getStatus() != 200) {
            throw new Exception($response->getBody());
        }
    }

    public function getSendStats()
    {
        //Build the parameters
        $params = array(
            'Action' => 'GetSendStatistics'
        );

        // Create client
        $client = new Zend_Http_Client_AmazonSES_SV4($this->_host);
        $client->setMethod(Zend_Http_Client::POST);
        $client->setParameterPost($params);

        // hhvm Invalid chunk size fix - force HTTP 1.0
        $client->setConfig(array(
            'httpversion' => Zend_Http_Client::HTTP_0,
        ));
        // -----

        // Add authorization header
        $client->setHeaders(array(
            'Authorization' => $client->buildAuthKey(new DateTime('NOW'), strtolower($this->_region), 'email', $this->_accessKey, $this->_privateKey)
        ));

        // Send request
        $response = $client->request(Zend_Http_Client::POST);

        if ($response->getStatus() != 200) {
            throw new Exception($response->getBody());
        }

        return $response->getBody();
    }


    /**
     * Format and fix headers
     *
     * Some SMTP servers do not strip BCC headers. Most clients do it themselves as do we.
     *
     * @access  protected
     * @param array $headers
     * @return  void
     * @throws  Zend_Transport_Exception
     */
    protected function _prepareHeaders($headers)
    {
        if (!$this->_mail) {
            /**
             * @see Zend_Mail_Transport_Exception
             */
            throw new Zend_Mail_Transport_Exception('_prepareHeaders requires a registered Zend_Mail object');
        }

        unset($headers['Bcc']);

        // Prepare headers
        parent::_prepareHeaders($headers);
    }


    /**
     * Returns header string containing encoded authentication key
     *
     * @param date $date
     * @return  string
     */
    private function _buildAuthKey($date)
    {
        return sprintf('AWS3-HTTPS AWSAccessKeyId=%s,Algorithm=HmacSHA256,Signature=%s', $this->_accessKey, base64_encode(hash_hmac('sha256', $date, $this->_privateKey, TRUE)));
    }
}
