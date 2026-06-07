version = "1"

mock "minimal" {
  ssh {
    user    = "ubuntu"
    keypair = "KEYPATH_PLACEHOLDER"
  }
}

keypair default {
  file_path = "KEYPATH_PLACEHOLDER"
}

vms web {
  count  = 1
  cpu    = 2
  memory = 1024
  disk {
    from = "registry/debian:13"
    size = "20Gi"
  }
}
