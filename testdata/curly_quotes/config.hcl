version = "1"

weft “smartquotes” {
  ssh {
    user    = “root”
    keypair = keypair.smart
  }
}

keypair smart {
  file_path = “KEYPATH_PLACEHOLDER”
}
