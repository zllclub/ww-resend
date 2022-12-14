package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zserge/lorca"
)

//go:embed www
var fs embed.FS

var ui lorca.UI

var clientNum int32

var hex bool = true

var resend bool = true

var serverlistener net.Listener

var serverConns []net.Conn

var serverConnsMap map[string]net.Conn = make(map[string]net.Conn)

var clientConn net.Conn

var clientConnsMap = struct {
	sync.RWMutex
	m map[string]net.Conn
}{m: make(map[string]net.Conn)}

var CurrentIp string
var CurrentPort string

// Go types that are bound to the UI must be thread-safe, because each binding
// is executed in its own goroutine. In this simple case we may use atomic
// operations, but for more complex cases one should use proper synchronization.
type counter struct {
	sync.Mutex
	count int32
}

func SetHexSwitch(isHex bool) {
	hex = isHex
}
func SetResendSwitch(isResend bool) {
	resend = isResend
}

func (c *counter) SetCount(n int32) {
	c.Lock()
	defer c.Unlock()
	c.count = n
}

func (c *counter) Value() int32 {
	c.Lock()
	defer c.Unlock()
	return c.count
}

func GetSystemMetrics(nIndex int) int {
	ret, _, _ := syscall.NewLazyDLL(`User32.dll`).NewProc(`GetSystemMetrics`).Call(uintptr(nIndex))
	return int(ret)
}

func openHtml() {
	args := []string{}
	if runtime.GOOS == "linux" {
		args = append(args, "--class=Lorca")
	}
	myUi, err := lorca.New("", "", 1200, 700, args...)
	ui = myUi
	if err != nil {
		log.Fatal(err)
	}
	defer ui.Close()
	ui.SetBounds(lorca.Bounds{
		Left:   GetSystemMetrics(0)/2 - 600,
		Top:    GetSystemMetrics(1)/2 - 350,
		Width:  1200,
		Height: 700,
	})
	// A simple way to know when UI is ready (uses body.onload event in JS)
	ui.Bind("start", func() {
		log.Println("UI is ready")
	})

	// Create and bind Go object to the UI
	c := &counter{}
	ui.Bind("counterValue", c.Value)
	ui.Bind("createServer", CreateServer)
	ui.Bind("createClient", CreateClient)
	ui.Bind("closeServer", CloseServer)
	ui.Bind("closeClient", CloseClient)
	ui.Bind("setHexSwitch", SetHexSwitch)
	ui.Bind("setResendSwitch", SetResendSwitch)
	ui.Bind("closeDotClient", CloseDotClient)
	ui.Bind("getIpAndPort", GetIpAndPort)
	ui.Bind("fillIpAndPort", FillIpAndPort)
	ui.Bind("appendIp", AppendIp)
	ui.Bind("sendToClient", SendToClient)
	ui.Bind("sendToServer", SendToServer)
	// Load HTML.
	// You may also use `data:text/html,<base64>` approach to load initial HTML,
	// e.g: ui.Load("data:text/html," + url.PathEscape(html))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, http.FileServer(http.FS(fs)))
	ui.Load(fmt.Sprintf("http://%s/www", ln.Addr()))

	// You may use console.log to debug your JS code, it will be printed via
	// log.Println(). Also exceptions are printed in a similar manner.
	// Wait until the interrupt signal arrives or browser window is closed
	sigc := make(chan os.Signal)
	signal.Notify(sigc, os.Interrupt)
	select {
	case <-sigc:
	case <-ui.Done():
	}
	log.Println("exiting...")
}

func main() {
	openHtml()
}

func GetIpAndPort(ip string, port string) {
	CurrentIp = ip
	CurrentPort = port
}
func reflushIpAndPort() {
	ui.Eval(`sendIpAndPort();`)
}

// TCP ?????????

//process ????????????
func process(conn net.Conn) {
	defer conn.Close()
	fmt.Println("?????????????????????:", conn.RemoteAddr().String())
	ui.Eval(`addLog('` + GetFullTime() + "================= ???????????? " + conn.RemoteAddr().String() + " =================" + `', true, '` + GetSuffix(conn.RemoteAddr().String()) + `');`)
	ui.Eval(`addLog('` + GetFullTime() + "================= ???????????? " + conn.RemoteAddr().String() + " =================" + `', true, '` + "home" + `');`)
	clientNum += 1
	if resend {
		reflushIpAndPort()
		now := time.Now()
		go CreateResendClient(CurrentIp, CurrentPort, conn)
		for {
			if time.Now().Unix()-now.Unix() > 2 {
				fmt.Println("????????????:")
				conn.Close()
				break
			}
			clientConnsMap.RLock()
			con := clientConnsMap.m[conn.RemoteAddr().String()]
			clientConnsMap.RUnlock()
			if con != nil {
				fmt.Println("???????????????????????????:")
				break
			}
		}

	}
	for {
		reader := bufio.NewReader(conn)
		var buf [1024]byte
		// ????????????
		read, err := reader.Read(buf[:])
		if err != nil {
			if resend {
				clientConnsMap.RLock()
				if clientConnsMap.m[conn.RemoteAddr().String()] != nil {
					clientConnsMap.m[conn.RemoteAddr().String()].Close()
					delete(clientConnsMap.m, conn.RemoteAddr().String())
				}
				clientConnsMap.RUnlock()
			}
			fmt.Println("????????????:", conn.RemoteAddr().String())
			suf := GetSuffix(conn.RemoteAddr().String())
			ui.Eval(`dotDisConn('` + suf + `');`)
			ui.Eval(`addLog('` + GetFullTime() + "================= ???????????? " + conn.RemoteAddr().String() + " =================" + `', true, '` + GetSuffix(conn.RemoteAddr().String()) + `');`)
			ui.Eval(`addLog('` + GetFullTime() + "================= ???????????? " + conn.RemoteAddr().String() + " =================" + `', true, '` + "home" + `');`)

			delete(serverConnsMap, suf)
			serverConns = DeleteArrayElement(serverConns, conn)
			clientNum -= 1
			if clientNum < 1 {
				ui.Eval(`clientDisconn();`)
			}
			break
		}
		// if err != nil {
		// 	fmt.Println("read from client failed,err =", err)
		// 	break
		// }
		//recvStr := string(buf[:read])
		recvStr := string(buf[:read])
		if hex {
			recvStr = getPrintString(buf[:read])
		}
		//ui.Eval(`addLog('` + GetTime() + recvStr + `', true, '` + GetSuffix(conn.RemoteAddr().String()) + `');`)
		printLog(recvStr, true, conn)
		if resend {
			clientConnsMap.RLock()
			clientConnsMap.m[conn.RemoteAddr().String()].Write(buf[:read])
			clientConnsMap.RUnlock()
		}

		fmt.Println("??????client?????????????????????", recvStr)
		//conn.Write([]byte(recvStr))
	}
}

func GetTime() string {
	return "[" + time.Now().Format("15:04:05.000") + "] "
}

func GetFullTime() string {
	return "[" + time.Now().Format("2006-01-02 15:04:05.000") + "] "
}

func GetIpStr(ip string) string {
	return "[" + ip + "] "
}

func CreateServer(port string) {
	listen, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Println("listen failed,err =", err)
		ui.Eval(`alertFunc('????????????` + port + `??????');
		         serverSwitch(false);`)
		return
	}
	serverlistener = listen
	for {
		// ????????????
		conn, err := listen.Accept()
		if err != nil {
			if conn == nil {
				fmt.Println("??????????????????:", port)
				return
			}
			fmt.Println("accept failed,err =", err)
			continue
		}
		serverConns = append(serverConns, conn)
		suf := GetSuffix(conn.RemoteAddr().String())
		serverConnsMap[suf] = conn
		ui.Eval(`clientConn();
		addScrollContainer('` + suf + `','` + conn.RemoteAddr().String() + `');`)
		go process(conn)
	}
}

func CloseServer() {
	//???????????????????????????
	if len(serverConns) > 0 {
		for i := 0; i < len(serverConns); i++ {
			if serverConns[i] != nil {
				serverConns[i].Close()

			}
		}
		serverConns = nil
		for k := range serverConnsMap {
			delete(serverConnsMap, k)
		}
	}
	if serverlistener != nil {
		err := serverlistener.Close()
		ui.Eval(`clientDisconn();`)
		clientNum = 0
		if err != nil {
			ui.Eval(`serverSwitch(false);`)
		}
	}
}
func DeleteArrayElement(list []net.Conn, ele net.Conn) []net.Conn {
	result := make([]net.Conn, 0)
	for _, v := range list {
		if v.RemoteAddr().String() != ele.RemoteAddr().String() {
			result = append(result, v)
		}
	}
	return result
}
func CloseDotClient(suf string) {
	if serverConnsMap[suf] == nil {
		return
	}
	serverConnsMap[suf].Close()
	serverConns = DeleteArrayElement(serverConns, serverConnsMap[suf])
	delete(serverConnsMap, suf)
	clientNum -= 1
	if clientNum < 1 {
		ui.Eval(`clientDisconn();`)
	}
}
func CloseClient() {
	if clientConn != nil {
		err := clientConn.Close()
		clientConn = nil
		ui.Eval(`clientSwitch(false);`)
		if err != nil {
			ui.Eval(`clientSwitch(true);`)
		}
	}
}

func CreateClient(ip string, port string) {
	//1. ????????????
	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		fmt.Println("Failed to Dial")
		ui.Eval(`alertFunc('????????????` + ip + ":" + port + `??????');
				 clientSwitch(false);`)
		return
	}
	CurrentIp = ip
	CurrentPort = port
	AppendIp(ip, port, "", false)
	// ???????????????????????????
	defer conn.Close()
	ui.Eval(`clientSwitch(true);`)
	ui.Eval(`client2ServerStatusSwitch('` + "home" + `',true);`)
	ui.Eval(`addLog('` + GetFullTime() + "================= ??????????????? " + conn.RemoteAddr().String() + " =================" + `', false, '` + "home" + `');`)
	clientConn = conn
	// 2. ??????????????????
	buf := make([]byte, 1024)
	for {
		// 2.1 ????????????????????????
		// readBytesCount, _ := os.Stdin.Read(buf)
		// //2.2 ????????????(??????????????????)
		// conn.Write(buf[:readBytesCount])
		//2.3 ?????????(??????????????????)
		readBytesCount, err := conn.Read(buf)
		if err == io.EOF {
			clientConn = nil
			fmt.Println("?????????????????????:", conn.RemoteAddr().String(), conn.LocalAddr().String())
			ui.Eval(`client2ServerStatusSwitch('` + "home" + `',false);`)
			ui.Eval(`addLog('` + GetFullTime() + "================= ??????????????? " + conn.RemoteAddr().String() + " =================" + `', false, '` + "home" + `');`)
			ui.Eval(`clientSwitch(false);`)
			break
		}
		if err != nil {
			clientConn = nil
			fmt.Println("?????????????????????:", conn.RemoteAddr().String(), conn.LocalAddr().String())
			ui.Eval(`client2ServerStatusSwitch('` + "home" + `',false);`)
			ui.Eval(`addLog('` + GetFullTime() + "================= ??????????????? " + conn.RemoteAddr().String() + " =================" + `', false, '` + "home" + `');`)
			fmt.Println("??????:", conn.RemoteAddr().String())
			ui.Eval(`clientSwitch(false);`)
			break
		}
		//2.4 ??????????????????
		//?????????buf[:n]?????????????????????buf[?????????-n]???buf[n]????????????
		recvStr := string(buf[:readBytesCount])
		if hex {
			recvStr = getPrintString(buf[:readBytesCount])
		}
		//ui.Eval(`addLog('` + GetTime() + recvStr + `', false, '` + GetSuffix(conn.RemoteAddr().String()) + `');`)
		printLog(recvStr, false, conn)
		fmt.Println("??????server??????????????????:", recvStr)
	}

}

func CreateResendClient(ip string, port string, targetConn net.Conn) {
	//1. ????????????
	conn, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		fmt.Println("Failed to Dial")
		ui.Eval(`clientSwitch(false);`)
		return
	}
	// ???????????????????????????
	defer conn.Close()
	ui.Eval(`client2ServerStatusSwitch('` + GetSuffix(targetConn.RemoteAddr().String()) + `',true);`)
	clientConnsMap.Lock()
	clientConnsMap.m[targetConn.RemoteAddr().String()] = conn
	clientConnsMap.Unlock()
	fmt.Println("??????????????????", conn.LocalAddr().String())
	ui.Eval(`addLog('` + GetFullTime() + "================= ??????????????? " + conn.RemoteAddr().String() + " =================" + `', false, '` + "home" + `');`)
	// 2. ??????????????????
	buf := make([]byte, 1024)
	for {
		// 2.1 ????????????????????????
		// readBytesCount, _ := os.Stdin.Read(buf)
		// //2.2 ????????????(??????????????????)
		// conn.Write(buf[:readBytesCount])
		//2.3 ?????????(??????????????????)
		readBytesCount, err := conn.Read(buf)
		if err == io.EOF {
			ui.Eval(`client2ServerStatusSwitch('` + GetSuffix(targetConn.RemoteAddr().String()) + `',false);`)
			fmt.Println("?????????????????????:", conn.RemoteAddr().String(), conn.LocalAddr().String())
			ui.Eval(`addLog('` + GetFullTime() + "================= ??????????????? " + conn.RemoteAddr().String() + " =================" + `', false, '` + GetSuffix(targetConn.RemoteAddr().String()) + `');`)
			ui.Eval(`addLog('` + GetFullTime() + "================= ??????????????? " + conn.RemoteAddr().String() + " =================" + `', false, '` + "home" + `');`)
			targetConn.Close()
			break
		}
		if err != nil {
			fmt.Println("??????:", conn.RemoteAddr().String())
			ui.Eval(`client2ServerStatusSwitch('` + GetSuffix(targetConn.RemoteAddr().String()) + `',false);`)
			ui.Eval(`addLog('` + GetFullTime() + "================= ??????????????? " + conn.RemoteAddr().String() + " =================" + `', false, '` + GetSuffix(targetConn.RemoteAddr().String()) + `');`)
			ui.Eval(`addLog('` + GetFullTime() + "================= ??????????????? " + conn.RemoteAddr().String() + " =================" + `', false, '` + "home" + `');`)
			targetConn.Close()
			break
		}
		//2.4 ??????????????????
		//?????????buf[:n]?????????????????????buf[?????????-n]???buf[n]????????????
		recvStr := string(buf[:readBytesCount])
		if hex {
			recvStr = getPrintString(buf[:readBytesCount])
		}
		//ui.Eval(`addLog('` + GetTime() + recvStr + `', false, '` + GetSuffix(conn.RemoteAddr().String()) + `');`)
		if resend {
			targetConn.Write(buf[:readBytesCount])
		}
		printLog(recvStr, false, targetConn)
		fmt.Println("??????server??????????????????:", recvStr)
	}

}

func printLog(recvStr string, toServer bool, conn net.Conn) {
	toServerStr := "false"
	if toServer {
		toServerStr = "true"
	}
	ui.Eval(`addLog('` + GetTime() + `', ` + toServerStr + `, '` + GetSuffix(conn.RemoteAddr().String()) + `','` + escapeHtml(recvStr) + `');`)
	ui.Eval(`addLog('` + GetFullTime() + GetIpStr(conn.RemoteAddr().String()) + `', ` + toServerStr + `, '` + "home" + `','` + escapeHtml(recvStr) + `');`)
}
func GetSuffix(address string) string {
	return strings.Replace(strings.Replace(address, ":", "_", 1), ".", "_", -1)
}
func escapeHtml(content string) string {
	if !hex {
		return getPrintString([]byte(content))
	}
	return content
}
func getPrintString(bytes []byte) string {
	var result string
	for i := 0; i < len(bytes); i++ {
		result += fmt.Sprintf("%02x", bytes[i])
	}
	return result
}

func getBytesByString(str string) []byte {
	byteStr := []rune(str)
	length := len(byteStr)
	var bytes []byte
	for i := 0; i < length; i += 2 {
		byteOne := []rune{byteStr[i], byteStr[i+1]}
		num, err := strconv.ParseUint(string(byteOne), 16, 8)
		if err != nil {
			return bytes
		}
		bytes = append(bytes, uint8(num))

	}
	return bytes
}

/**
 * ????????????????????????  ???????????? true ???????????????false
 */
func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

// ??????`json:"ip"`??????.?????????????????????????????????
type IpConfig struct {
	Ip    string `json:"ip"`
	Port  string `json:"port"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type IpConfigWrapper struct {
	ipconfig []IpConfig
	by       func(p, q *IpConfig) bool
}

func FillIpAndPort() {
	json := getConfigAndPort()
	ui.Eval(`fillIpItem('` + json + `');`)
}
func getConfigAndPort() string {
	var ips []IpConfig
	//????????????????????????
	filer, _ := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0666)
	defer filer.Close()
	reader := bufio.NewReader(filer)
	for {
		str, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		//????????????
		var ic IpConfig
		errs := json.Unmarshal([]byte(str), &ic)
		if errs != nil {
			continue
		}
		ips = append(ips, ic)
	}
	//?????????
	jsons, _ := json.Marshal(ips)
	return string(jsons)
}

var path string = "resend-ip.config"

func AppendIp(ip string, port string, name string, del bool) {
	var ips []IpConfig
	//????????????????????????
	filer, _ := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0666)
	defer filer.Close()
	reader := bufio.NewReader(filer)
	for {
		str, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		//????????????
		var ic IpConfig
		errs := json.Unmarshal([]byte(str), &ic)
		if errs != nil {
			continue
		}
		ips = append(ips, ic)
	}
	ipConfigMap := make(map[string]IpConfig)
	for i := 0; i < len(ips); i++ {
		ipConfigMap[ips[i].Ip+ips[i].Port] = ips[i]
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Println("??????????????????", err)
	}
	//????????????file??????
	defer file.Close()
	//???????????????????????????????????? *Writer
	write := bufio.NewWriter(file)
	var ic IpConfig
	ic.Ip = ip
	ic.Port = port
	if name != "" {
		ic.Name = name
	}
	if v, ok := ipConfigMap[ic.Ip+ic.Port]; ok {
		ic.Count = v.Count + 1
		if v.Name != "" && name == "" {
			ic.Name = v.Name
		}

	}
	ipConfigMap[ic.Ip+ic.Port] = ic
	if del {
		delete(ipConfigMap, ic.Ip+ic.Port)
	}
	IpConfigMapValues := make([]IpConfig, 0, len(ipConfigMap))
	for k := range ipConfigMap {
		IpConfigMapValues = append(IpConfigMapValues, ipConfigMap[k])
	}
	SortPerson(IpConfigMapValues, func(p, q *IpConfig) bool {
		return q.Count < p.Count
	})
	for i := 0; i < len(IpConfigMapValues); i++ {
		//?????????
		jsons, _ := json.Marshal(IpConfigMapValues[i])
		if jsons != nil {
			write.WriteString(string(jsons) + "\n")
		}
	}
	//Flush??????????????????????????????????????????
	write.Flush()
}

//??????????????????????????????
type SortBy func(p, q *IpConfig) bool

func (pw IpConfigWrapper) Len() int { // ?????? Len() ??????
	return len(pw.ipconfig)
}
func (pw IpConfigWrapper) Swap(i, j int) { // ?????? Swap() ??????
	pw.ipconfig[i], pw.ipconfig[j] = pw.ipconfig[j], pw.ipconfig[i]
}
func (pw IpConfigWrapper) Less(i, j int) bool { // ?????? Less() ??????
	return pw.by(&pw.ipconfig[i], &pw.ipconfig[j])
}

// ????????? SortPerson ??????
func SortPerson(people []IpConfig, by SortBy) {
	sort.Sort(IpConfigWrapper{people, by})
}

func SendToServer(targer string, content string) {
	if content == "" {
		return
	}
	if targer == "" {
		if clientConn != nil {
			if hex {
				clientConn.Write(getBytesByString(content))
			} else {
				clientConn.Write([]byte(content))
			}
			ui.Eval(`addLocalLog('` + GetFullTime() + GetIpStr("local") + content + `', ` + "true" + `, '` + "home" + `');`)
		}
		return
	}

	clientConnsMap.RLock()
	con := clientConnsMap.m[targer]
	if con != nil {
		if hex {
			con.Write(getBytesByString(content))
		} else {
			con.Write([]byte(content))
		}
		printLocalLog(content, true, con)
	}
	clientConnsMap.RUnlock()
}

func SendToClient(targer string, content string) {
	if content == "" || targer == "" {
		return
	}

	scon := serverConnsMap[targer]
	if scon != nil {
		if hex {
			scon.Write(getBytesByString(content))
		} else {
			scon.Write([]byte(content))
		}
		printLocalLog(content, false, scon)
	}
}

func printLocalLog(recvStr string, toServer bool, conn net.Conn) {
	toServerStr := "false"
	if toServer {
		toServerStr = "true"
	}
	ui.Eval(`addLocalLog('` + GetTime() + `', ` + toServerStr + `, '` + GetSuffix(conn.RemoteAddr().String()) + `','` + escapeHtml(recvStr) + `');`)
	ui.Eval(`addLocalLog('` + GetFullTime() + GetIpStr(conn.RemoteAddr().String()) + `', ` + toServerStr + `, '` + "home" + `','` + escapeHtml(recvStr) + `');`)
}
