version = "1"

vms weft-full-web {
  count  = 2
  cpu    = 4
  mem    = 2048
  disk {
    from = "image.debian.from"
    size = "20Gi"
  }
  disk data1 {
    size       = "10Gi"
    mountpoint = "/mnt/${self.label}"
  }
  disk data2 {
    size       = "10Gi"
    mountpoint = join("/", ["/data", self.label])
  }
  disk quoted {
    size       = "5Gi"
    mountpoint = "/srv/quoted"
  }
  script = <<-CLOUD_INIT
    #!/bin/bash
    echo hello
  CLOUD_INIT
  ssh {
    user    = "deploy"
    keypair = keypair.shared
  }
}

vms weft-full-app {
  count  = 1
  cpu    = 2
  memory = 1024
  disk {
    from = "image.alpine-arm.from"
    size = "10Gi"
  }
  script = <<RAW_SCRIPT
echo raw
RAW_SCRIPT
}

vms weft-full-disabled {
  count = 0
}

vms weft-full-keepath {
  count  = 1
  cpu    = 1
  memory = 512
  disk {
    from = "registry-1.docker.io/library/debian:13"
    size = "5Gi"
  }
  ssh {
    user    = "root"
    keypair = "KEYPATH_PLACEHOLDER"
  }
}
