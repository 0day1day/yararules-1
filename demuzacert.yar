rule PotentiallyCompromisedCert

{
    meta:
        description = "Search for PE files using cert issued to DEMUZA "
        author = "Brian Carter"
        last_modified = "July 21, 2017"
        TLP = "WHITE"

    strings:
        $magic = { 50 4b 03 04 (14 | 0a) 00 }

        $txt1 = "demuza@yandex.ru" nocase
        $txt2 = "https://secure.comodo.net/CPS0C" nocase
        $txt3 = "COMODO CA Limited1"

    condition:
       $magic at 0 and all of ($txt*)
}
