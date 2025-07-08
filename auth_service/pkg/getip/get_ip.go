package getip

import(
	"net/http"
	"strings"
	"net"
)

func GetIP(r *http.Request) string {
	// Проверка X-Forwarded-For (может быть список IP через запятую)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// Берём первый IP из списка
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Проверка X-Real-IP
	if realIP := r.Header.Get("X-Real-Ip"); realIP != "" {
		return realIP
	}

	// Fallback на RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // на крайний случай
	}
	return ip
}
