package rule

func isPublicBinding(ip string) bool {
switch ip {
case "0.0.0.0", "::", "[::]":
return true
default:
return false
}
}
