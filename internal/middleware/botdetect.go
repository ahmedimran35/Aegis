package middleware

import (
	"log"
	"net/http"
	"strings"
)

var goodBots = []string{
	"googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
	"yandexbot", "sogou", "exabot", "facebot", "ia_archiver",
	"linkedinbot", "pinterestbot", "twitterbot", "whatsapp",
	"applebot", "discordbot", "telegrambot",
}

var badBots = []string{
	"nikto", "sqlmap", "nmap", "nessus", "burp", "dirbuster",
	"gobuster", "wfuzz", "hydra", "medusa", "wpscan", "joomscan",
	"acunetix", "netsparker", "appscan", "w3af", "skipfish",
	"arachni", "openvas", "masscan", "zgrab",
}

var suspiciousAgents = []string{
	"curl", "wget", "httpie", "python-requests", "python-urllib",
	"go-http-client", "java/", "perl", "ruby", "libwww",
	"httrack", "mechanize", "scrapy",
}

// BotDetectionMiddleware categorizes requests by user-agent plus basic behavioral heuristics.
func BotDetectionMiddleware(mode string) Middleware {
	if mode == "off" {
		return func(next http.Handler) http.Handler { return next }
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ua := strings.ToLower(r.UserAgent())

			if ua == "" {
				if mode == "block" {
					log.Printf("bot: blocked empty user-agent from %s", extractIP(r))
					writeBlockError(w, "BOT_BLOCKED", "empty user-agent not allowed")
					return
				}
				log.Printf("bot: empty user-agent from %s", extractIP(r))
			}

			// Check good bots — skip bad-bot blocking but still pass through Aegis rules
			isGoodBot := false
			for _, bot := range goodBots {
				if strings.Contains(ua, bot) {
					isGoodBot = true
					break
				}
			}

			// Check bad bots — block or log (skip for good bots)
			if !isGoodBot {
				for _, bot := range badBots {
					if strings.Contains(ua, bot) {
						if mode == "block" {
							log.Printf("bot: blocked bad bot %q from %s", bot, extractIP(r))
							writeBlockError(w, "BOT_BLOCKED", "automated attack tool detected")
							return
						}
						log.Printf("bot: detected bad bot %q from %s", bot, extractIP(r))
						break
					}
				}
			}

			// Check suspicious agents — log only
			for _, agent := range suspiciousAgents {
				if strings.Contains(ua, agent) {
					log.Printf("bot: suspicious agent %q from %s", agent, extractIP(r))
					break
				}
			}

			// Behavioral heuristic 1: block if Accept header is missing (commonly omitted by crawlers)
			if r.Header.Get("Accept") == "" && ua != "" {
				if mode == "block" {
					log.Printf("bot: blocked missing Accept header from %s", extractIP(r))
					writeBlockError(w, "BOT_BLOCKED", "missing Accept header")
					return
				}
				log.Printf("bot: suspicious missing Accept header from %s", extractIP(r))
			}

			// Behavioral heuristic 2: block if neither Accept-Language nor Referer is present
			// Only flag if User-Agent is present (API clients may legitimately lack these)
			if ua != "" && r.Header.Get("Accept-Language") == "" && r.Header.Get("Referer") == "" {
				if mode == "block" {
					log.Printf("bot: blocked missing Accept-Language/Referer from %s", extractIP(r))
					writeBlockError(w, "BOT_BLOCKED", "missing required headers")
					return
				}
				log.Printf("bot: suspicious missing Accept-Language/Referer from %s", extractIP(r))
			}

			next.ServeHTTP(w, r)
		})
	}
}

