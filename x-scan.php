<?php 
/* 
____  ___           _________                     
\   \/  /          /   _____/ ____ _____    ____  
 \     /   ______  \_____  \_/ ___\\__  \  /    \ 
 /     \  /_____/  /        \  \___ / __ \|   |  \
/___/\  \         /_______  /\___  >____  /___|  /
      \_/                 \/     \/     \/     \/ 
--------------https://abaykan.com/-----------------
[ X-Scan | Evil Code Finder ][ Code by Abay ]
Script ini memungkinkan kita menemukan file tersembunyi milik attacker. 
Bahkan memungkinkan untuk melacak gambar yang tertanam kode yang bisa dieksekusi.
*/ 
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<head> 
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8"> 
<meta http-equiv="Content-Language" content="en-us">
<title>X-Scan | Evil Code Finder</title> 
</head> 
<body> 
<pre align="center">
+============================================================================================================+
____  ___           _________                     
\   \/  /          /   _____/ ____ _____    ____  
 \     /   ______  \_____  \_/ ___\\__  \  /    \ 
 /     \  /_____/  /        \  \___ / __ \|   |  \
/___/\  \         /_______  /\___  >____  /___|  /
      \_/                 \/     \/     \/     \/ 
------------------------https://abaykan.com/----------------------------
[ X-Scan | Evil Code Finder ][ Code by Abay ]<br>
Script ini memungkinkan kita menemukan file tersembunyi milik attacker.
Bahkan memungkinkan untuk melacak gambar yang tertanam kode yang bisa dieksekusi.
+============================================================================================================+
</pre><br>
<hr color="black" style="opacity: 0.3"><br>
<p>
<?php 
// SET MAXIMUM EXECUTION TIME TO UNLIMITED (0) BECAUSE THE SCRIPT CAN TAKE A WHILE.
// YOU COULD USE A MORE CONSERVATIVE TIME LIMIT SUCH AS 1 HOUR (3600 SECONDS), JUST IN CASE.
// THESE HAVE NO EFFECT IF YOU RUN PHP IN "SAFE MODE" (SAFE MODE IS USUALLY UNDESIRABLE ANYWAY). 
ini_set('max_execution_time', '0');
ini_set('set_time_limit', '0');

// --------------------------------------------------------------------------------
// UTILITY FUNCTIONS.
// OUTPUT TEXT IN SPECIFIED COLOR, CLEANING IT WITH HTMLENTITIES().
function CleanColorText($text, $color)
{
$outputcolor = 'black';
$color = trim($color);
if(preg_match('/^(red|blue|green|black)$/i', $color))
$outputcolor = $color;
return '<span style="color:' . $outputcolor . ';">' . htmlentities($text, ENT_QUOTES) . '</span>';
}

// --------------------------------------------------------------------------------
// THIS FUNCTION RECURSIVELY FINDS FILES AND PROCESSES THEM THROUGH THE SPECIFIED CALLBACK FUNCTION.
// DIFFERENT TYPES OF FILES NEED TO BE HANDLED BY DIFFERENT CALLBACK FUNCTIONS.

function find_files($path, $pattern, $callback) 
{
// CHANGE BACKSLASHES TO FORWARD, WHICH IS OK IN PHP, EVEN IN WINDOWS.
// REMOVE ANY TRAILING SLASHES, THEN ADD EXACTLY ONE.
$path = rtrim(str_replace("\\", "/", $path), '/') . '/'; 
if(!is_readable($path))
{
echo "Warning: Unable to open and enter directory " . CleanColorText($path, 'blue') . 
". Check its owner/group permissions.<br>";
return;
}
$dir = dir($path); 
$entries = array(); 
while(($entry = $dir->read()) !== FALSE) 
$entries[] = $entry; 
$dir->close(); 
foreach($entries as $entry) 
{ 
$fullname = $path . $entry; 
if(($entry !== '.') && ($entry !== '..') && is_dir($fullname))
find_files($fullname, $pattern, $callback); 
else
if(is_file($fullname) && preg_match($pattern, $entry)) 
call_user_func($callback, $fullname); 
} 
} 

// --------------------------------------------------------------------------------
// CALLBACK FUNCTIONS.
// CALLBACK FUNCTION TO LOOK FOR MALICIOUS CODE - YOU COULD ADD ANY OTHER MALICIOUS CODE SNIPPETS YOU KNOW OF. 
function maliciouscodesnippets($filename) 
{ 
if(stripos($filename, "x-scan.php")) // DON'T FLAG THIS FILE WHICH I CALLED x-scan.php 
return; 

if(!is_readable($filename))
{
echo "Warning: Unable to read " . CleanColorText($filename, 'blue') . 
". Check it manually and check its access permissions.<br>";
return;
}
$file = file_get_contents($filename); //READ THE FILE 

// PRINTING EVERY FILENAME GENERATES A LOT OF OUTPUT.
//echo CleanColorText($filename, 'green') . " is being examined.<br>"; 

// TEXT FILES WILL BE SEARCHED FOR THESE SNIPPETS OF SUSPICIOUS TEXT.
// THESE ARE REGULAR EXPRESSIONS WITH THE REQUIRED /DELIMITERS/ AND WITH SPECIAL CHARACTERS ESCAPED.
// /i AT THE END MEANS CASE INSENSITIVE.
$SuspiciousSnippets = array
(
// POTENTIALLY SUSPICIOUS PHP CODE
'/edoced_46esab/i',
'/passthru *\(/i',
'/shell_exec *\(/i',
'/document\.write *\(unescape *\(/i',

// THESE CAN GIVE MANY FALSE POSITIVES WHEN CHECKING WORDPRESS AND OTHER CMS.
// NONETHELESS, THEY CAN BE IMPORTANT TO FIND, ESPECIALLY BASE64_DECODE.
'/base64_decode *\(/i',
'/system *\(/i', 
'/`.+`/', // BACKTICK OPERATOR INVOKES SYSTEM FUNCTIONS, SAME AS system()
// '/phpinfo *\(/i',
// '/chmod *\(/i',
// '/mkdir *\(/i',
// '/fopen *\(/i',
// '/fclose *\(/i',
// '/readfile *\(/i',

// SUSPICIOUS NAMES. SOME HACKERS SIGN THEIR SCRIPTS. MANY NAMES COULD GO HERE,
// HERE IS A GENERIC EXAMPLE. YOU CAN FILL IN WHATEVER NAMES YOU WANT.
'/hacked by /i',
'/touched by /i',
'/pawnedz by /i',
'/pwned by /i',
'/pwnedz by /i',
'/pwndz by /i',
'/pwnd by /i',

// OTHER SUSPICIOUS TEXT STRINGS
'/web[\s-]*shell/i', // TO FIND BACKDOOR WEB SHELL SCRIPTS.
'/c99/i', // THE NAMES OF TWO POPULAR WEB SHELLS.
'/r57/i',
'/idx/i',
'/b374k/i',
'/indoxploit/i',

// YOU COULD ADD IN THE SPACE BELOW SOME REGULAR EXPRESSIONS TO MATCH THE NAMES OF MALICIOUS DOMAINS 
// AND IP ADDRESSES MENTIONED IN YOUR GOOGLE SAFEBROWSING DIAGNOSTIC REPORT. SOME EXAMPLES:
'/gumblar\.cn/i',
'/martuz\.cn/i',
'/beladen\.net/i',
'/gooqle/i', // NOTE THIS HAS A Q IN IT.

// THESE 2 ARE THE WORDPRESS CODE INJECTION IN FRONT OF EVERY INDEX.PHP AND SOME OTHERS 
'/_analist/i',
'/anaiytics/i' // THE LAST ENTRY IN THE LIST MUST HAVE NO COMMA AFTER IT.
);

foreach($SuspiciousSnippets as $i) 
{
// STRPOS/STRIPOS WERE A LITTLE FASTER BUT LESS FLEXIBLE
if(preg_match($i, $file)) 
echo CleanColorText($filename, 'blue') . ' MATCHES REGEX: ' . CleanColorText($i, 'red') . '<br>'; 
}

if(!strpos($filename,"network.php") && !strpos($filename,"rewrite.php") && stripos($file,"RewriteRule")) 
echo CleanColorText($filename, 'blue') . " contains " . CleanColorText("RewriteRule", 'red') . 
" - check it manually for malicious redirects.<br>"; 

/*
// THIS FINDS ALL JAVASCRIPT CODE. IF ENABLED, IT WILL GIVE *MANY* FALSE POSITIVES IN MOST WEBSITES.
if($p = stripos($file, "<script ")) 
echo CleanColorText($filename, 'blue') . ' contains SCRIPT:<br>' . 
CleanColorText(substr($file, $p, 100), 'red') . '<br><br>'; 
*/
/*
// THIS FINDS ALL IFRAMES. IF ENABLED, IT CAN GIVE MANY FALSE POSITIVES IN SOME WEBSITES.
if($p = stripos($file, "<iframe ")) 
echo CleanColorText($filename, 'blue') . ' contains IFRAME:<br>' . 
CleanColorText(substr($file, $p, 100), 'red') . '<br><br>'; 
*/

if(stripos($file, "AddHandler")) 
{
// THIS IS HOW THEY MAKE THE IMAGE FILES EXECUTABLE.
echo CleanColorText($filename, 'blue') . " contains " . CleanColorText('AddHandler', 'red') . 
" - make sure it does not make ordinary files like images executable.<br>"; 
// IF YOU FIND NINE ZILLION OF THESE, UNCOMMENT IT BECAUSE IT IS A PAIN TO DELETE THEM BY HAND.
// BUT CHECK THE LIST CAREFULLY FIRST TO MAKE SURE YOU REALLY WANT TO DELETE 
// ALL THE FILES AND NONE OF THEM ARE FALSE POSITIVES. 
//unlink($filename); // THIS DELETES THE FILE WITHOUT GIVING YOU THE OPTION OF EXAMINING IT!
} 
} 

// CALLBACK FUNCTION TO REPORT PHARMA LINK HACKS.
function pharma($filename) 
{ 
echo CleanColorText($filename, 'blue') . " is most likely a " . CleanColorText('pharma hack', 'red') . ".<br>"; 
} 

// CALLBACK FUNCTION TO REPORT FILES WHOSE NAMES ARE SUSPICIOUS.
function badnames($filename) 
{ 
echo CleanColorText($filename, 'blue') . " is a " . CleanColorText('suspicious file name', 'red') . ".<br>"; 
} 

// --------------------------------------------------------------------------------
// SET UP THE SEARCH CRITERIA.

// SEARCHES WILL BE DONE IN THIS DIRECTORY AND ALL DIRS INSIDE IT. 
// './' MEANS CURRENT DIRECTORY, WHERE THIS SCRIPT IS NOW.
// THUS, TO SEARCH EVERYTHING INSIDE PUBLIC_HTML, THAT'S WHERE THIS FILE SHOULD BE PUT.
// TO SEARCH OUTSIDE PUBLIC_HTML, OR TO SEARCH A FOLDER OTHER THAN WHERE THIS SCRIPT IS STORED, 
// CHANGE THIS TO THE FULL PATHNAME, SUCH AS /home/userid/ OR /home/userid/public_html/somefolder/
// USE FORWARD SLASHES FOR PATH. WINDOWS EXAMPLE: C:/wamp/apache2/htdocs/test/
$StartPath = './';

// ENTRIES IN THE FOLLOWING 3 ARRAYS ARE REGULAR EXPRESSIONS, WHICH IS THE REASON FOR THE /DELIMITERS/.
// FILES WHOSE NAMES MATCH THESE REGEXES WILL HAVE THEIR TEXT SEARCHED FOR MALICIOUS CODE.
$FiletypesToSearch = array
(
'/\.htaccess$/i',
'/\.php[45]?$/i',
'/\.html?$/i',
'/\.aspx?$/i',
'/\.inc$/i',
'/\.cfm$/i',
'/\.js$/i',
'/\.php.pjpeg$/i',
'/\.php.xxxjpg$/i',
'/\.php5$/i',
'/\.phtml$/i',
'/\.css$/i'
);

// FILES OR FOLDERS WITH THESE STRINGS IN THEIR *NAMES* WILL BE REPORTED AS SUSPICIOUS.
$SuspiciousFileAndPathNames = array
(
// '/root/i',
// '/kit/i',
'/c99/i',
'/r57/i',
'/idx/i',
'/indoxploit/i',
'/gifimg/i'
);

// FILENAMES RELATED TO WORDPRESS PHARMA HACK, USING THE NAMING CONVENTIONS 
// DESCRIBED AT http://www.pearsonified.com/2010/04/wordpress-pharma-hack.php 
// FILES MATCHING THESE NAMES WILL BE REPORTED AS POSSIBLE PHARMA HACK FILES.
$PharmaFilenames = array
(
'/^\..*(cache|bak|old)\.php/i', // HIDDEN FILES WITH PSEUDO-EXTENSIONS IN THE MIDDLE OF THE FILENAME
'/^db-.*\.php/i',

// PERMIT THE STANDARD WORDPRESS FILES THAT START WITH CLASS-, BUT FLAG ALL OTHERS AS SUSPICIOUS.
// THE (?!) IS CALLED A NEGATIVE LOOKAHEAD ASSERTION. IT MEANS "NOT FOLLOWED BY..."

'/^class-(?!snoopy|smtp|feed|pop3|IXR|phpmailer|json|simplepie|phpass|http|oembed|ftp-pure|wp-filesystem-ssh2|wp-filesystem-ftpsockets|ftp|wp-filesystem-ftpext|pclzip|wp-importer|wp-upgrader|wp-filesystem-base|ftp-sockets|wp-filesystem-direct)\.php/i'
);

// --------------------------------------------------------------------------------
// FINALLY, DO THE SEARCHES, USING THE ABOVE ARRAYS AS THE STRING DATA SOURCES.

// REPORT FILES WITH SUSPICIOUS NAMES
foreach($SuspiciousFileAndPathNames as $i)
find_files($StartPath, $i, 'badnames'); 

// REPORT FILES WITH SUSPICIOUS PHARMA-RELATED NAMES
foreach($PharmaFilenames as $i)
find_files($StartPath, $i, 'pharma'); 

// REPORT FILES CONTAINING SUSPICIOUS CODE OR TEXT
foreach($FiletypesToSearch as $i)
find_files($StartPath, $i, 'maliciouscodesnippets');
echo "<hr color='black'>";
echo "<br>Done<br>"; 

?> 

</p> 
</body> 
</html>