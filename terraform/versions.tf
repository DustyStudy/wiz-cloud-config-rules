terraform {
  required_version = ">= 1.9"

  required_providers {
    wiz = {
      source  = "tf.app.wiz.io/wizsec/wiz"
      version = ">= 1.28"
    }
  }
}
