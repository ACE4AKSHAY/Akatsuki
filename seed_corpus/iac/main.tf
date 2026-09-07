# EXPECTED_FINDINGS: [{"primitive":"aws_kms_key","category":"key-management","line":1},{"primitive":"azurerm_key_vault_key","category":"key-management","line":5},{"primitive":"google_kms_key_ring","category":"key-management","line":12}]
resource "aws_kms_key" "a" {
  description             = "test"
  deletion_window_in_days = 7
}

resource "azurerm_key_vault_key" "b" {
  name         = "example"
  key_vault_id = "x"
  key_type     = "RSA"
  key_size     = 2048
}

resource "google_kms_key_ring" "c" {
  name     = "ring"
  location = "global"
}
