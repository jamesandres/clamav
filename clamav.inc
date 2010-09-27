<?php
// $Id$
/**
 * @file clamav.inc
 * API and helper functions for the ClamAV module.
 */

/**
 * Scan a file and raise an error on the form element (if required).
 *
 * @param String $filepath     Path to the file to test
 * @param String $form_element The form element to set an error on.
 *                             E.g. foo
 *                             E.g. foo][bar][baz
 */
function clamav_scan($filepath, $form_element) {
  $result = clamav_scan_file($filepath);

  if($result == CLAMAV_SCANRESULT_INFECTED) {
    form_set_error($form_element, t('A virus has been detected in the file.  The file will not be accepted.'));
  }
  elseif ($result == CLAMAV_SCANRESULT_UNCHECKED && variable_get('clamav_unchecked_files', CLAMAV_DEFAULT_UNCHECKED) == CLAMAV_BLOCK_UNCHECKED) {
    form_set_error($form_element, t('The anti-virus scanner was not able to check the file.  The file cannot be uploaded.'));
  }
}

/**
 * Scan a single file
 *
 * @param String $filepath
 *
 * @return int
 * one of:
 * - CLAMAV_SCANRESULT_UNCHECKED
 * - CLAMAV_SCANRESULT_CLEAN
 * - CLAMAV_SCANRESULT_INFECTED
 */
function clamav_scan_file($filepath) {
  switch(variable_get('clamav_mode', CLAMAV_DEFAULT_MODE)) {
    case CLAMAV_USE_DAEMON:
      return _clamav_scan_via_daemon($filepath);

    case CLAMAV_USE_EXECUTABLE:
      return _clamav_scan_via_exec($filepath);
  }
}


/**
 * Scan a single file using a daemon.
 * TODO: support INSTREAM, so the clamav-daemon does not need access to the
 *       file.  This will allow a separate clamav-daemon to service a number of
 *       web-instances.
 *
 * @param String $filepath
 *
 * @return int
 * one of:
 * - CLAMAV_SCANRESULT_UNCHECKED
 * - CLAMAV_SCANRESULT_CLEAN
 * - CLAMAV_SCANRESULT_INFECTED
 */
function _clamav_scan_via_daemon($filepath) {
  $host = variable_get('clamav_daemon_host', CLAMAV_DEFAULT_HOST);
  $port = variable_get('clamav_daemon_port', CLAMAV_DEFAULT_PORT);

  // try to open a socket to clamav
  $handler = ($host && $port) ? @fsockopen($host, $port) : FALSE;

  if(!$handler) {
    watchdog('clamav', "The clamav module is not configured for daemon mode.  The uploaded file could not be scanned.", WATCHDOG_WARNING);
    return CLAMAV_SCANRESULT_UNCHECKED;
  }

  // request a scan from the daemon
  fwrite($handler, "SCAN {$filepath}\n");
  $response = fgets($handler);
  fclose($handler);

  // clamd returns a string response in the format:
  // filename: OK
  // filename: <name of virus> FOUND
  // filename: <error string> ERROR

  if (preg_match('/.*: OK$/', $response)) {
    return CLAMAV_SCANRESULT_CLEAN;
  }
  elseif (preg_match('/.*: (.*) FOUND$/', $response, $matches)) {
    $virus_name = $matches[1];
    watchdog('clamav', 'Virus detected in uploaded file.  Clamav-daemon reported the virus:<br />@virus_name', array('@virus_name' => $virus_name), WATCHDOG_CRITICAL);
    return CLAMAV_SCANRESULT_INFECTED;
  }
  else {
    // try to extract the error message from the response.
    preg_match('/.*: (.*) ERROR$/', $response, $matches);
    $error_string = $matches[1]; // the error message given by the daemon
    watchdog('clamav', 'Uploaded file could not be scanned.  Clamscan reported:<br />@error_string', array('@error_string' => $error_string), WATCHDOG_WARNING);

    return CLAMAV_SCANRESULT_UNCHECKED;
  }
}


/**
 * Scan a single file using a clamav executable.
 *
 * @param String $filepath
 *
 * @return int
 * one of:
 * - CLAMAV_SCANRESULT_UNCHECKED
 * - CLAMAV_SCANRESULT_CLEAN
 * - CLAMAV_SCANRESULT_INFECTED
 */
function _clamav_scan_via_exec($filepath) {
  // get the path to the executable
  $executable = variable_get('clamav_executable_path', CLAMAV_DEFAULT_PATH);

  // check that the executable is available
  if (!file_exists($executable)) {
    watchdog('clamav', "The clamscan executable could not be found at %path", array('%path' => $executable), WATCHDOG_ERROR);
    return CLAMAV_SCANRESULT_UNCHECKED;
  }

  // using 2>&1 to grab the full command-line output.
  $cmd = escapeshellcmd($executable) .' '. escapeshellarg($filepath) . ' 2>&1';
  
  // exec:
  // The lines of text output by clamscan are assigned as an array to $output
  // The actual result of clamscan is assigned to $result:
  // 0 = clean
  // 1 = infected
  // x = unchecked
  exec($cmd, $output, $result);


  /**
   * clamscan return values (documented from man clamscan)
   *  0 : No virus found.
   *  1 : Virus(es) found.
   * 40: Unknown option passed.
   * 50: Database initialization error.
   * 52: Not supported file type.
   * 53: Can't open directory.
   * 54: Can't open file. (ofm)
   * 55: Error reading file. (ofm)
   * 56: Can't stat input file / directory.
   * 57: Can't get absolute path name of current working directory.
   * 58: I/O error, please check your file system.
   * 62: Can't initialize logger.
   * 63: Can't create temporary files/directories (check permissions).
   * 64: Can't write to temporary directory (please specify another one).
   * 70: Can't allocate memory (calloc).
   * 71: Can't allocate memory (malloc).
   */
  switch($result) {
    case 0:
      return CLAMAV_SCANRESULT_CLEAN;

    case 1:
      // pass each line of the exec output through checkplain.
      // The t operator ! is used instead of @, because <br /> tags are being added.
      foreach($output as $key => $line) {
        $output[$key] = check_plain($line);
      }
      watchdog('clamav', 'Virus detected in uploaded file.  Clamscan reported:<br />!clamscan_output', array('!clamscan_output' => implode('<br />', $output)), WATCHDOG_CRITICAL);
      return CLAMAV_SCANRESULT_INFECTED;

    default:
      $descriptions = array(
        40 => "Unknown option passed.",
        50 => "Database initialization error.",
        52 => "Not supported file type.",
        53 => "Can't open directory.",
        54 => "Can't open file. (ofm)",
        55 => "Error reading file. (ofm)",
        56 => "Can't stat input file / directory.",
        57 => "Can't get absolute path name of current working directory.",
        58 => "I/O error, please check your file system.",
        62 => "Can't initialize logger.",
        63 => "Can't create temporary files/directories (check permissions).",
        64 => "Can't write to temporary directory (please specify another one).",
        70 => "Can't allocate memory (calloc).",
        71 => "Can't allocate memory (malloc).",
      );
      $description = (array_key_exists($result, $descriptions)) ? $descriptions[$result] : 'unknown error';

      watchdog('clamav', 'Uploaded file could not be scanned.  Clamscan reported: [@error_code] - @error_description', array('@error_code' => $result, '@error_description' => $description), WATCHDOG_WARNING);
      return CLAMAV_SCANRESULT_UNCHECKED;
  }
}


/**
 * Get the version information for clamav.
 *
 * @param Mixed $settings For executable:
 *                          String: path to the clamscan executable
 *                        For daemon:
 *                          Array: providing the keys 'host' and 'port'
 *
 * @return String
 * The version string, as provided by clamav.
 */
function clamav_get_version($settings) {
  if(is_string($settings) && !empty($settings)) {
    return _clamav_get_version_via_exec($settings);
  }
  elseif(is_array($settings) && isset($settings['host']) && isset($settings['port'])) {
    return _clamav_get_version_via_daemon($settings['host'], $settings['port']);
  }
}


/**
 * Get version information from a clamav executable.
 *
 * @param String $executable_path
 *
 * @return String
 */
function _clamav_get_version_via_exec($executable_path) {
  return exec(escapeshellcmd($executable_path) . ' -V');
}

/**
 * Get version information from a clamav daemon.
 *
 * @param String $host
 * @param Int    $port
 * 
 * @return String
 */
function _clamav_get_version_via_daemon($host, $port) {
  $handler = @fsockopen($host, $port);
  if (!$handler) {
    return NULL;
  }

  fwrite($handler, "VERSION\n");
  $content = fgets($handler);
  fclose($handler);
  return $content;
}
