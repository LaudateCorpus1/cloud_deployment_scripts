/*
 * Copyright (c) 2019 Teradici Corporation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

locals {
  prefix = var.prefix != "" ? "${var.prefix}-" : ""

  # Windows computer names must be <= 15 characters, minus 4 chars for "-xyz"
  # where xyz is number of instances (0-999)
  host_name = substr("${local.prefix}${var.name}", 0, 11)

  enable_public_ip = var.enable_public_ip ? [true] : []
  startup_script = "centos-std-startup.sh"
}

resource "google_storage_bucket_object" "centos-std-startup-script" {
  name    = local.startup_script
  bucket  = var.bucket_name
  content = templatefile(
    "${path.module}/${local.startup_script}.tmpl",
    {
      pcoip_registration_code  = var.pcoip_registration_code,
      domain_controller_ip     = var.domain_controller_ip,
      domain_name              = var.domain_name,
      service_account_username = var.service_account_username,
      service_account_password = var.service_account_password,
    }
  )
}

resource "google_compute_instance" "centos-std" {
  count = var.instance_count

  provider     = google
  name         = "${local.host_name}-${count.index}"
  machine_type = var.machine_type

  boot_disk {
    initialize_params {
      #image = "projects/${var.disk_image_project}/global/images/family/${var.disk_image_family}"
      image = "projects/${var.disk_image_project}/global/images/${var.disk_image}"
      type  = "pd-ssd"
      size  = var.disk_size_gb
    }
  }

  network_interface {
    subnetwork = var.subnet

    dynamic access_config {
      for_each = local.enable_public_ip
      content {}
    }
  }

  tags = [
    "${local.prefix}tag-ssh",
    "${local.prefix}tag-icmp",
  ]

  metadata = {
    ssh-keys = "${var.ws_admin_user}:${file(var.ws_admin_ssh_pub_key_file)}"
    startup-script-url = "gs://${var.bucket_name}/${google_storage_bucket_object.centos-std-startup-script.output_name}"
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}
