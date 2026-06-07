version = "1"

mock “smartquotes” {
  ssh {
    user    = “root”
    keypair = keypair.smart
  }
}

keypair smart {
  file_path = “KEYPATH_PLACEHOLDER”
}
