version = "1"

// Variable assignments
var registry = "ghcr.io/openweft"
var team     = "platform"

weft "full" {
  authorized_keys_path = "~/.ssh/authorized_keys"
  parallelism          = 4
  adapter              = adapter.TART

  cache {
    path = "/var/cache/weft"
  }

  vms {
    path = "/var/lib/weft/vms"
  }

  ssh {
    user    = "ubuntu"
    keypair = "KEYPATH_PLACEHOLDER"
  }

  timeout {
    pull_post_completion = "30s"
    wait_ssh             = 120
    up                   = "5m"
  }
}

keypair shared {
  file_path = "KEYPATH_PLACEHOLDER"
}

keypair "with-hyphen" {
  file_path = "KEYPATH_PLACEHOLDER"
}

log {
  file            = "/var/log/weft.log"
  level           = "info"
  max_mb          = 100
  timeout_seconds = 60
}

endpoint docker {
  url = "registry-1.docker.io"
}

endpoint quay {
  url = "quay.io"
}

image debian {
  from = "registry-1.docker.io/library/debian:13"
}

image alpine-arm {
  from = join("/", [var.registry, "alpine-${arch.oci}:latest"])
}

image rocky10 {
  from     = join("/", [endpoint.docker.url, "library/rocky-${arch.gnu}:10"])
  checksum = "registry-1.docker.io/library/rocky-${arch.gnu}.sha256"
}

image cloudimg {
  from     = "https://cloud.example.com/debian-13-${arch.oci}.qcow2"
  checksum = "https://cloud.example.com/debian-13-${arch.oci}.sha256"
}
