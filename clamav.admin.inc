<?php
// $Id$

/**
 * @file
 *  Menu and FAPI callbacks for ClamAV admin settings page.
 */

/**
 * Admin settings page for ClamAV
 */
function clamav_admin_settings() {
  module_load_include('inc', 'clamav');

  $form = array();

  $form['antivirus'] = array('#type' => 'fieldset', '#title' => t('ClamAV'), '#collapsible' => TRUE, '#collapsed' => FALSE);
  $form['antivirus']['clamav_clamav'] = array(
    '#type'          => 'checkbox',
    '#title'         => t('Enable <a href="http://www.clamav.net" title="ClamAV">ClamAV</a> anti-virus scans'),
    '#default_value' => CLAMAV_CLAMAV,
  );
  $form['antivirus']['clamav_clamav_method'] = array(
    '#type'          => 'radios',
    '#title'         => t('Select anti-virus scan method'),
    '#options'       => array(FALSE => t('Connect to a \'clamav-daemon\' TCP socket'), TRUE => t('Run a \'clamscan\' program')),
    '#default_value' => CLAMAV_CLAMAV_METHOD,
    '#description'   => t('A preferable way is to use a \'clamav-daemon\' since it ensures much faster performance then a \'clamscan\' program. Daemon should have a read access to the web server\'s temporal files in order to scan them.'),
  );
  $form['antivirus']['clamav_clamav_allow'] = array(
    '#type'          => 'radios',
    '#title'         => t('Allow file uploads if the daemon is not running or program is not found'),
    '#options'       => array(FALSE => t('No'), TRUE => t('Yes')),
    '#default_value' => CLAMAV_CLAMAV_ALLOW,
    '#description'   => t('Choose if you want to allow file uploads when scan is enabled, but the daemon is not running or program is not found.'),
  );
  // Deamon.
  $clamav_daemon_version = _clamav_check_clamav(array('host' => CLAMAV_CLAMAV_HOST, 'port' => CLAMAV_CLAMAV_PORT, 'version' => TRUE));
  $clamav_daemon_version = preg_match('/ClamAV/', $clamav_daemon_version) ? $clamav_daemon_version : NULL;
  $message = isset($clamav_daemon_version) ? t('The \'clamav-daemon\' %version is found at %host:%port.', array('%host' => CLAMAV_CLAMAV_HOST, '%port' => CLAMAV_CLAMAV_PORT, '%version' => $clamav_daemon_version)) : t('The clamav-daemon is not found at %host:%port.', array('%host' => CLAMAV_CLAMAV_HOST, '%port' => CLAMAV_CLAMAV_PORT));
  $form['daemon'] = array('#type' => 'fieldset', '#title' => t('ClamAV daemon'), '#description' => t('These settings will be used if you have chosen "Connect to a \'clamav-daemon\' TCP socket" above. ') . $message, '#collapsible' => TRUE, '#collapsed' => FALSE);
  $form['daemon']['clamav_clamav_host'] = array(
    '#type'          => 'textfield',
    '#title'         => t('\'clamav-daemon\' host'),
    '#default_value' => CLAMAV_CLAMAV_HOST,
    '#maxlength'     => 255,
    '#description'   => t('A hostname \'clamav-daemon\' is running on. For most cases it will run on the same machine as a webserver.'),
  );
  $form['daemon']['clamav_clamav_port'] = array(
    '#type'          => 'textfield',
    '#title'         => t('\'clamav-daemon\' TCP port'),
    '#default_value' => CLAMAV_CLAMAV_PORT,
    '#size'          => 6,
    '#maxlength'     => 8,
    '#description'   => t('A TCP port \'clamav-daemon\' is listening to. Default port for the daemon is 3310.'),
  );
  // Utility.
  $form['utility'] = array('#type' => 'fieldset', '#title' => t('ClamAV program'), '#description' => t('These settings will be used if you have chosen "Run a \'clamscan\' program" above.'), '#collapsible' => TRUE, '#collapsed' => FALSE);
  if ($clamav_utility_path = exec('which clamscan 2>/dev/null')) {
    $clamav_utility_version = _clamav_check_clamav(array('path' => $clamav_utility_path));
    $clamav_utility_version = preg_match('/ClamAV/', $clamav_utility_version) ? $clamav_utility_version : NULL;
  }
  $message = isset($clamav_utility_version) ? t('The \'clamscan\' %version is found at %path. If the field is left empty the default utility will be used.', array('%path' => $clamav_utility_path, '%version' => $clamav_utility_version)) : t('The \'clamscan\' is not found. Please, specify the full path.');
  $form['utility']['clamav_clamav_path'] = array(
    '#type'          => 'textfield',
    '#title'         => t('A path to the scanning utility \'clamscan\''),
    '#default_value' => CLAMAV_CLAMAV_PATH,
    '#maxlength'     => 255,
    '#description'   => t('Full path to the \'clamscan\' utility.') .' '. $message,
  );

  return system_settings_form($form);
}

