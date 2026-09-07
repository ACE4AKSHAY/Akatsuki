# EXPECTED_FINDINGS: [{"library":"golang.org/x/crypto","primitive":"x/crypto","category":"key-management","line":1}]
module example.com/demo

go 1.22

require (
    golang.org/x/crypto v0.21.0
    github.com/labstack/echo/v4 v4.11.4
)
