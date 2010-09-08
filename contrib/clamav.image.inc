<?php
// $Id$

/**
 * @file clamav.image.inc
 *  Image module integration for ClamAV.
 */

/**
 * Delegated implementation of hook_form_alter()
 */
function clamav_image_form_alter(&$form, $form_state, $form_id) {
  if (!isset($form['type']) || !isset($form['#node'])) {
    if ($form['type']['#value'] .'_node_form' != $form_id) {
      return;
    }
  }

  $node = $form['#node'];

  // Add validator before all others
  array_unshift($form['#validate'], 'clamav_image_validate');
}

/**
 * FAPI form validator for image_form()
 */
function clamav_image_validate($form, &$form_state) {
  if ($_FILES['files']['tmp_name']['image']) {
    $file = (object) array(
      'filepath' => $_FILES['files']['tmp_name']['image'],
      'filename' => $_FILES['files']['name']['image'],
    );

    if (($result = clamav_scan($file)) && $result[0] != TRUE) {
      form_set_error('files[image]', $result[1]);
    }
  }
}

