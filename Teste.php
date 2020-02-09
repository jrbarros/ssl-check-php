<?php declare(strict_types=1);


namespace JrBarros;

require  'vendor/autoload.php';

class Teste
{

    public function teste()
    {
        $var = ['name' => 'Portal do Aluno', 'url' => 'https://portal.influx.com.br'];

        $resul =  (new CheckSSL())->add($var)->check();

      return  print_r($resul);
    }
}

(new Teste())->teste();