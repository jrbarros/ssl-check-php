<?php declare(strict_types=1);


namespace JrBarros;


use DateTime;
use DateTimeZone;
use http\Encoding\Stream;
use RuntimeException;

/**
 * Class CheckSSL
 * @package JrBarros
 */
class CheckSSL
{

    /**
     * @var array
     */
    protected array $url;

    /**
     * @var array
     */
    protected array $result;
    /**
     * @var string
     */
    private string $dateFormat;
    /**
     * @var string
     */
    private ?string $timeZone;
    private $formatString;

    /**
     * CheckSSL constructor.
     * @param array $url
     * @param string $dateFormat
     * @param string $timeZone
     * @param string $formatString
     */
    public function __construct(array $url = [], $dateFormat = 'U', $timeZone = null, $formatString = 'Y-m-d\TH:i:s\Z')
    {
        $this->url = $url;
        $this->dateFormat = $dateFormat;
        $this->timeZone = $timeZone;
        $this->formatString = $formatString;
    }

    /**
     * @param array $data
     * @return CheckSSL
     * @throws \Exception
     */
    public function add(array $data): CheckSSL
    {
        if (empty($data['url'])) {
            throw new \Exception();
        }

        $data['url'] = parse_url($data['url'], PHP_URL_HOST);

        $this->url[] = array_merge($this->url, $data);

        return $this;
    }

    public function getUrls()
    {
        return $this->url;
    }

    /**
     * @return array
     * @throws \Exception
     */
    public function check(): array
    {
        foreach ($this->url as $item) {

            $cert = $this->getCert($item['url']);

            if ($cert === false) {
               // TODO: tratar error de uma URL
                continue;
            }

           $this->result[] = $item['result'] = $this->getSLLInformation($cert);

        }

        return $this->getResults();
    }

    /**
     * @param resource $read
     * @return array('valid_from' => \DateTime,'valid_to'=> \DateTime)
     * @throws \Exception
     */
    private function getSLLInformation($siteStream) : array
    {
        try {

            if (! is_resource($siteStream) || get_resource_type($siteStream) !== 'stream' ) {
                throw new RuntimeException('param $siteStream not type stream');
            }

            $certStream = stream_context_get_params($siteStream);

            $cert = $this->getCertFromArray($certStream);

            $certInfo = openssl_x509_parse($cert);

            $valid_from = $this->normalizeDate((string) $certInfo['validFrom_time_t']);
            $valid_to   = $this->normalizeDate((string) $certInfo['validTo_time_t']);
        } catch (\Exception $exception) {
            throw new RuntimeException($exception->getMessage());
        }

        return [
            'valid_from' => $valid_from,
            'valid_to'   => $valid_to
        ];

    }

    private function getResults()
    {
        return $this->result;
    }

    /**
     * @return resource
     */
    private function getStreamContext()
    {
        return stream_context_create(
            [
                'ssl' => [
                    'capture_peer_cert' => true
                ]
            ]
        );
    }

    /**
     * @param $url
     * @return false|resource
     */
    private function getCert($url)
    {
        try {
            $messageError = 'error to get certificate';
            $cert = stream_socket_client(
                'ssl://' . $url. ':443',
                $errno, $messageError, 30,
                STREAM_CLIENT_CONNECT, $this->getStreamContext()
            );
        } catch (\Exception $exception)  {
            throw new RuntimeException($exception->getMessage());
        }

        return  $cert;

    }

    /**
     * @param $timeStamp
     * @return string|false
     */
    private function normalizeDate($timeStamp)
    {
        $timeZone = null;

        if ($this->timeZone !== null) {
            $timeZone = new DateTimeZone($this->timeZone);
        }

        return DateTime::createFromFormat($this->dateFormat, $timeStamp, $timeZone)->format($this->formatString);
    }


    /**
     * @param $certStream
     * @return resource
     */
    public function getCertFromArray($certStream)
    {
        $this->certStreamValidation($certStream);

        return $certStream['options']['ssl']['peer_certificate'];
    }

    /**
     * @param $certStream
     * @return bool
     */
    private function certStreamValidation($certStream): bool
    {
        if (! is_array($certStream) ||
            ! array_key_exists('options', $certStream)||
            ! array_key_exists('ssl', $certStream['options']) ||
            ! array_key_exists('peer_certificate', $certStream['options']['ssl']) ||
            ! is_resource($certStream['options']['ssl']['peer_certificate']) ||
            get_resource_type($certStream['options']['ssl']['peer_certificate']) !== 'OpenSSL X.509') {

            throw  new RuntimeException('param $certStream not type OpenSSL X.509');
        }

        return true;
    }
}