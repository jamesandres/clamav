<?php
// $Id$

/**
 * @file clamav.filefield.inc
 *  Filefield / imagefield integration for ClamAV
 */

/**
 * Delegated implementation of hook_form_alter()
 */
function clamav_filefield_form_alter(&$form, $form_state, $form_id) {
  if (!isset($form['type']) || !isset($form['#node'])) {
    if ($form['type']['#value'] .'_node_form' != $form_id) {
      return;
    }
  }

  $node = $form['#node'];

  $info = _content_type_info();
  $fields = $info['content types'][$node->type]['fields'];

  // TODO: Loop over all fields, find the filefield ones attach extra validation
  // handlers onto each one.

  foreach ($fields as $field_name => $field) {
    if ($field['type'] != 'filefield') {
      continue;
    }

    $children = element_children($form[$field_name]);
    foreach ($children as $delta) {
      if (!is_numeric($delta) || $delta < 0) {
        continue;
      }

      $form[$field_name][$delta]['#upload_validators']['clamav_filefield_scan'] = array();
    }
  }
}

/**
 * An #upload_validators callback. Check the file for viruses.
 */
function clamav_filefield_scan($file) {
  $errors = array();

  if (($result = clamav_scan($file)) && $result[0] != TRUE) {
    $errors[] = $result[1];
  }

  return $errors;
}

