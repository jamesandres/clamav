<?php
// $Id$

/**
 * @file clamav.inc
 *  ClamAV Scanner functions
 */

/**
 * Clamav file scan.
 */
function clamav_scan_clamav($file, $account = NULL) {
  if (!$account) {
    global $user;
    $account = $user;
  }

  if (CLAMAV_CLAMAV_METHOD) {
    // Command line.
    $clamav_path = CLAMAV_CLAMAV_PATH ? CLAMAV_CLAMAV_PATH : exec('which clamscan');
    if (!file_exists($clamav_path) || !_clamav_check_clamav(array('path' => $clamav_path))) {
      $file->scanned = FALSE;
      watchdog('clamav', 'The \'clamscan\' utility is not installed at %path.', array('%path' => $clamav_path), WATCHDOG_ERROR);
      if (!CLAMAV_CLAMAV_ALLOW)
        return t('Antivirus utility is not found on the system. Please contact site administrator.');
      else
        return NULL;
    }
    if (exec(escapeshellcmd($clamav_path) .' '. escapeshellarg($file->filepath), $output)) {
      if (preg_match('/FOUND$/', $output[0])) {
        $result = preg_replace('/^.* (\S+) FOUND$/', '$1', $output[0]);
        watchdog('clamav', 'The file %file uploaded by %user contained a virus %virus and was deleted.', array('%file' => $file->filename, '%user' => $user->name, '%virus' => $result), WATCHDOG_NOTICE);
        return t('A virus %virus has been found in the uploaded file.', array('%virus' => $result));
      }
      else {
        watchdog('clamav','Clam output : !output', array('!output' => $output[0]));
        watchdog('clamav', 'The file %file uploaded by %user and scanned by ClamAV is not infected.', array('%file' => $file->filename, '%user' => $user->name), WATCHDOG_NOTICE);
      }
    }
  }
  else {
    // Daemon.
    if (!_clamav_check_clamav(array('host' => CLAMAV_CLAMAV_HOST, 'port' => CLAMAV_CLAMAV_PORT))) {
      $file->scanned = FALSE;
      watchdog('clamav', 'The \'clamav-daemon\' is not running at %host host %port port.', array('%host' => CLAMAV_CLAMAV_HOST, '%port' => CLAMAV_CLAMAV_PORT), WATCHDOG_ERROR);
      if (!CLAMAV_CLAMAV_ALLOW)
        return t('Antivirus daemon is not running on the system. Please contact site administrator.');
      else
        return NULL;
    }
    $handler = @fsockopen(CLAMAV_CLAMAV_HOST, CLAMAV_CLAMAV_PORT);
    if (!$handler) {
      watchdog('clamav', 'The \'clamav-daemon\' is not running at %host host %port port.', array('%host' => CLAMAV_CLAMAV_HOST, '%port' => CLAMAV_CLAMAV_PORT), WATCHDOG_ERROR);
      return NULL;
    }
    fwrite($handler, 'SCAN '. $file->filepath ."\n");
    $content = fgets($handler);
    fclose($handler);
    if (preg_match('/ERROR/', $content)) {
      watchdog('clamav', 'The \'clamav-daemon\' SCAN command failed to scan a file %file with the following error %error.', array('%file' => $file->filename, '%error' => $content), WATCHDOG_ERROR);
      return NULL;
    }
    if (preg_match('/FOUND$/', $content)) {
      $result = preg_replace('/^.* (\S+) FOUND\n$/', '$1', $content);
      watchdog('clamav', 'The file %file uploaded by %user contained a virus %virus and was deleted.', array('%file' => $file->filename, '%user' => $user->name, '%virus' => $result), WATCHDOG_NOTICE);
      return t('A virus %virus has been found in the uploaded file.', array('%virus' => $result));
    }
    else {
      watchdog('clamav','Clam output : !output', array('!output' => $output[0]));
      watchdog('clamav', 'The file %file uploaded by %user and scanned by ClamAV is not infected.', array('%file' => $file->filename, '%user' => $user->name), WATCHDOG_NOTICE);
    }
  }

  return NULL;
}

/**
 * Clamav scanner check.
 */
function _clamav_check_clamav($data) {
  if (isset($data['path'])) {
    // clamscan utility
    return exec(escapeshellcmd($data['path']) .' -V');
  }
  if (isset($data['host']) && isset($data['port'])) {
    // tcp connection
    $handler = @fsockopen($data['host'], $data['port']);
    if (!$handler) {
      return NULL;
    }
    if (isset($data['version'])) {
      fwrite($handler, "VERSION\n");
      $content = fgets($handler);
      fclose($handler);
      return $content;
    }
    else {
      fwrite($handler, "PING\n");
      $content = fgets($handler);
      fclose($handler);
      if (preg_match('/PONG/', $content)) {
        return $content;
      }
    }
  }
  return NULL;
}

