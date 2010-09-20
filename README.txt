This is a forked version of the antivirus module found in File Framework (http://drupal.org/project/fileframework).

The plan is to release ClamAV as a separate project on Drupal.org and refactor File Framework to require ClamAV as a dependency.  This will allow:
  (1) Users, not be interested in the entire File Framework module, to have ClamAV support
  (2) Other contrib modules to integrate with a ClamAV in a standardised way

Help needed!  The File Framework module needs refactoring, contrib/antivirus needs removing and a dependency created on ClamAV.  Thread here: http://drupal.org/node/905600