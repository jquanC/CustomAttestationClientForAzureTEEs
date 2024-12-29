package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	// "github.com/zzGHzz/tls-node/comm"
)

/* configuration const */
const (
	address       = "localhost:8072"
	nonceClient   = "CCCCCCCCCCCC"              //set fixed in demo
	clientCredDir = "./script/client-cred"      //folder path to read client credentials(certs)
	serverCredDir = "./script/server-cred-recv" //folder path to store server credentials(certs)
)

// 定义签名算法映射
var algToSignatureAlgorithm = map[string]x509.SignatureAlgorithm{
	"RS256": x509.SHA256WithRSA,
	"RS384": x509.SHA384WithRSA,
	"RS512": x509.SHA512WithRSA,
	"PS256": x509.SHA256WithRSAPSS,
	"PS384": x509.SHA384WithRSAPSS,
	"PS512": x509.SHA512WithRSAPSS,
}

type JWTToken struct {
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
}

func main() {
	//1.client establish socket with server（ip:localhost, port:8071）
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()
	//2.client send: nonce(12-byte length in string format,assuming it is 'CCCCCCCCCCCC'), node1-ca.crt, node1-client.crt
	//2.1 Access these file. The directory path of all these files located：./script/client-cred
	//2.2 Sent to the server;
	sendMessage(conn, nonceClient)
	sendFile(conn, clientCredDir+"/node1-ca.crt")
	sendFile(conn, clientCredDir+"/node1-client.crt")
	//3. receive server nonce,node0-ca.crt, node0-client.crt; And store them in "./script/client-cred" folder
	serverNonce := receiveMessage(conn)
	fmt.Println("Server Nonce:", serverNonce)
	// saveFile(serverNonce, serverCredDir+"/nonce.txt")
	receiveFile(conn, serverCredDir+"/node0-ca.crt")
	receiveFile(conn, serverCredDir+"/node0-server.crt")
	//4. client call a tool installed in the syatem, which is "AttestationClient", , and obtain the return result, stored in JWTResult; notice that the command is 'CCCCCCCCCCCC':
	//4.1 Command to call the "AttestationClient": sudo AttestationClient -n "nonce" -o token
	extractPubkey := callOpensslGetPubkey(clientCredDir + "/node1-client.crt")
	extractPubkey = extractPubkeyFromPem(extractPubkey)
	fmt.Println("Extracted Public Key:", extractPubkey)
	jwtResult := callAttestationClient(serverNonce + extractPubkey)

	//5. client send JWTResult to server
	sendMessage(conn, jwtResult)
	//6. receive server JWTResult and print it
	serverJwtResult := receiveMessage(conn)
	fmt.Println("Recv Server JWT Result:", serverJwtResult)
	//7. validate server JWTResult by calling isValidJwt(to be continued)
	// isValid := isValidJwt(serverJwtResult)
	// isValid, err := validateJWT(serverJwtResult)
	isValid, err := validateJWTwithPSH(serverJwtResult)
	if err != nil {
		fmt.Println("Error validating JWT:", err)
	} else {
		fmt.Println("JWT Validation Result:", isValid)
	}

	//8.Print the function isValidJwt return result: true(valid) or false(invalid)
	fmt.Println("JWT Validation Result:", isValid)
	//9. Check the JWT token claims
	expectPubkey := callOpensslGetPubkey(serverCredDir + "/node0-server.crt")
	expectPubkey = extractPubkeyFromPem(expectPubkey)
	checkTee, checkPubkey, checkNonce, err := extractAndCheckJWTCliams(serverJwtResult, expectPubkey, nonceClient) //client check Server's JWT claims,should be the clientNonce
	if err != nil {
		fmt.Println("Error checking JWT claims:", err)
	} else {
		if checkNonce && checkPubkey && checkTee {
			fmt.Println("Vlidation of JWT Claims passed")
		} else {
			fmt.Println("Vlidation of JWT Claims failed")
		}
	}

	/*
		fmt.Println("Hello, World!")
		//Initialize  cfg
		cfg := &comm.Config{
			Name:       "client",
			Address:    "127.0.0.1:8087",
			ServerCert: "./credential/server.crt",
			ServerKey:  "./credential/server.key",
			ClientCert: "./credential/client.crt",
			ClientKey:  "./credential/client.key",
			CACert:     "./credential/ca.crt",
			Peers: []comm.PeerConfig{
				{
					Name:    "server",
					Address: "127.0.0.1:8086",
					CACert:  "./credential/ca.crt",
				},
				// {
				// 	Name:   "peer2",
				// 	Address: "127.0.0.1:8082",
				// 	CACert: "/path/to/peer2-ca-cert.pem",
				// },
			},
		}

		funcs := []func([]byte){}
		ports_len := 1 //
		for i := 0; i < ports_len; i++ {
			funcs = append(funcs, func(d []byte) {
				fmt.Printf("PRINT node=node%d msg: %s\n", i+1, string(d))
			})
		}
		handleMessageFunc := funcs[0]
		// communicator:= comm.NewCommunicator(cfg, handleMessageFunc)
		communicator, err := comm.NewCommunicator(cfg, handleMessageFunc)
		if err != nil {
			fmt.Printf("Error creating communicator: %v\n", err)
			return
		}
		communicator.Start()

		data := []byte("Data from client")
		peer := communicator.GetPeer("server")
		if peer != nil {
			peer.Write(data)
		}
		// communicator.Close()
	*/

}

func sendMessage(conn net.Conn, message string) {
	messageBytes := []byte(message)
	length := len(messageBytes)
	// 先发送长度
	// conn.Write([]byte(fmt.Sprintf("%d\n", length)))
	conn.Write([]byte{byte(length >> 8), byte(length)})
	conn.Write(messageBytes)
}

func receiveMessage(conn net.Conn) string {
	//长度
	lengthBuf := make([]byte, 2) // 假定长度不会超过16字节
	conn.Read(lengthBuf)

	length := int(lengthBuf[0])<<8 | int(lengthBuf[1])

	// 内容
	data := make([]byte, length)
	conn.Read(data)
	return string(data)
}

func sendFile(conn net.Conn, filePath string) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	length := len(data)
	conn.Write([]byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)})
	conn.Write(data)
}

func receiveFile(conn net.Conn, filePath string) {

	buf := make([]byte, 4)
	conn.Read(buf)
	length := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	data := make([]byte, length)
	conn.Read(data)
	ioutil.WriteFile(filePath, data, 0644)
}

/* func sendFile(conn net.Conn, filename string) {

	// 读取文件内容
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	// 先发送文件大小作为前缀
	size := len(data)
	sizeBytes := []byte(fmt.Sprintf("%d\n", size)) // 使用换行符分隔大小和数据
	conn.Write(sizeBytes)

	// 发送文件数据
	conn.Write(data)

} */

/* func sendMessage(conn net.Conn, message string) {
	// 先发送消息长度作为前缀
	size := len(message)
	sizeBytes := []byte(fmt.Sprintf("%d\n", size)) // 使用换行符分隔大小和数据
	conn.Write(sizeBytes)

	// 发送消息内容
	conn.Write([]byte(message))
} */

/* func receiveFile(conn net.Conn, filename string) {
	// 使用切片存储
	var fileData []byte
	buffer := make([]byte, 1024)

	for {
		// 读取数据
		n, err := conn.Read(buffer)
		if err != nil {
			if err == io.EOF {
				// 连接关闭，正常结束读取
				break
			}
			fmt.Println("Error reading file:", err)
			return
		}
		// 将读取到的数据追加到 fileData
		fileData = append(fileData, buffer[:n]...)
	}

	// 保存接收到的文件数据
	if err := ioutil.WriteFile(filename, fileData, 0644); err != nil {
		fmt.Println("Error writing file:", err)
	}
} */

/*
	 func receiveMessage(conn net.Conn) string {


			// buf := make([]byte, 1024)
			// n, err := conn.Read(buf)
			// if err != nil {
			// 	fmt.Println("Error receiving message:", err)
			// 	return ""
			// }
			// return string(buf[:n])

		var messageData []byte
		buffer := make([]byte, 1024)

		for {
			// 读取数据
			n, err := conn.Read(buffer)
			if err != nil {
				if err == io.EOF {
					break // 连接关闭，正常结束读取
				}
				fmt.Println("Error receiving message:", err)
				return ""
			}
			// 将读取到的数据追加到 messageData
			messageData = append(messageData, buffer[:n]...)
		}

		return string(messageData) // 返回完整的消息
	}
*/
/* func receiveFile(conn net.Conn, filename string) {
	// 读取文件大小
	sizeBuf := make([]byte, 1024)
	n, err := conn.Read(sizeBuf)
	if err != nil {
		fmt.Println("Error reading file size:", err)
		return
	}
	size, err := strconv.Atoi(string(sizeBuf[:n]))
	if err != nil {
		fmt.Println("Error converting file size:", err)
		return
	}

	// 创建缓冲区接收数据
	fileData := make([]byte, size)
	totalRead := 0
	for totalRead < size {
		n, err := conn.Read(fileData[totalRead:])
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		totalRead += n
	}

	// 保存接收到的文件数据
	if err := ioutil.WriteFile(filename, fileData, 0644); err != nil {
		fmt.Println("Error writing file:", err)
	}
} */

/*
	 func receiveMessage(conn net.Conn) string {
		// 读取消息大小
		sizeBuf := make([]byte, 1024)
		n, err := conn.Read(sizeBuf)
		if err != nil {
			fmt.Println("Error reading message size:", err)
			return ""
		}
		size, err := strconv.Atoi(string(sizeBuf[:n]))
		if err != nil {
			fmt.Println("Error converting message size:", err)
			return ""
		}

		// 创建缓冲区接收数据
		messageData := make([]byte, size)
		totalRead := 0
		for totalRead < size {
			n, err := conn.Read(messageData[totalRead:])
			if err != nil {
				fmt.Println("Error reading message:", err)
				return ""
			}
			totalRead += n
		}

		return string(messageData) // 返回完整的消息
	}
*/

/* Read the pubkey from the pem.file */
func extractPubkeyFromPem(pubkey string) string {
	// Remove all newline characters and split lines
	lines := strings.Split(pubkey, "\n")

	// Filter the lines, ignoring BEGIN and END lines
	var cleanedLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "-----BEGIN") || strings.HasPrefix(line, "-----END") || line == "" {
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}

	// Join the remaining lines back together
	return strings.Join(cleanedLines, "")
}
func callOpensslGetPubkey(filePath string) string {
	cmd := exec.Command("openssl", "x509", "-in", filePath, "-pubkey", "-noout")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error getting pubkey from certificate", err)
		return ""
	}
	return string(output)
}

func callAttestationClient(nonce string) string {
	cmd := exec.Command("sudo", "AttestationClient", "-n", nonce, "-o", "token")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error calling AttestationClient:", err)
		return ""
	}
	return string(output)
}

func saveFile(content, filename string) {
	ioutil.WriteFile(filename, []byte(content), 0644)
}

/* parse JWT into 3 parts */
func parseJWT(jwtToken string) (*JWTToken, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	header, payload, signature := parts[0], parts[1], parts[2]

	headerDecoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	payloadDecoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	var token JWTToken
	if err := json.Unmarshal(headerDecoded, &token.Header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %v", err)
	}

	if err := json.Unmarshal(payloadDecoded, &token.Payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	token.Signature = signature

	return &token, nil
}

func extractAndCheckJWTCliams(jwtToken, exptPubKey, exptNonce string) (bool, bool, bool, error) {
	// 1. parse JWT
	token, err := parseJWT(jwtToken)
	if err != nil {
		return false, false, false, err
	}

	// 2.  payload中读 x-ms-isolation-tee.x-ms-compliance-status 的值
	teeComplianceStatus, ok := token.Payload["x-ms-isolation-tee"].(map[string]interface{})["x-ms-compliance-status"].(string)
	checkTee := ok && strings.Contains(teeComplianceStatus, "compliant-cvm")

	// 3. payload中读 x-ms-runtime.client-payload.nonce 的值
	clientPayload, ok := token.Payload["x-ms-runtime"].(map[string]interface{})["client-payload"].(map[string]interface{})
	if !ok {
		return false, false, false, fmt.Errorf("missing x-ms-runtime.client-payload.nonce in payload")
	}
	noncePubkey, ok := clientPayload["nonce"].(string)
	if !ok {
		return false, false, false, fmt.Errorf("missing x-ms-runtime.client-payload.nonce in payload")
	}
	fmt.Println("NoncePubkey:", noncePubkey)
	// 4. 对 noncePubkey 执行 Base64URL decode
	// noncePubkeyDecode, err := base64.RawURLEncoding.DecodeString(noncePubkey)//for non-padding base64url encoding
	noncePubkeyDecode, err := base64.StdEncoding.DecodeString(noncePubkey)

	if err != nil {
		return false, false, false, fmt.Errorf("failed to decode noncePubkey: %v", err)
	}

	tokenNonce := string(noncePubkeyDecode[:12])
	tokenPubkey := string(noncePubkeyDecode[12:])
	checkPubkey := exptPubKey == tokenPubkey
	checkNonce := exptNonce == tokenNonce
	fmt.Println("TeeComplianceStatus:", teeComplianceStatus)
	fmt.Println("Token Nonce:", tokenNonce)
	fmt.Println("Token Pubkey:", tokenPubkey)
	if !checkTee {
		fmt.Println("TeeComplianceStatus is not compliant-cvm")
	}
	if !checkPubkey {
		fmt.Println("Public Key does not match")
	}
	if !checkNonce {
		fmt.Println("Nonce does not match")
	}

	return checkTee, checkPubkey, checkNonce, nil
}

func isValidJwt(token string) bool {
	// Implementation of JWT validation logic
	return true // Placeholder return
}

func validateJWTwithPSH(jwtToken string) (bool, error) {
	// 1. 保存当前工作目录
	currentDir, err := os.Getwd()
	if err != nil {
		return false, fmt.Errorf("failed to get current working directory: %v", err)
	}

	// 2. 设置工作目录
	workDir := "/home/azureuser/.local/scriptsRealtedAzureAttest"
	if err := os.Chdir(workDir); err != nil {
		return false, fmt.Errorf("failed to change directory to %s: %v", workDir, err)
	}

	// 3. 启动 PowerShell 环境
	cmd := exec.Command("sudo", "pwsh")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("./Confirm-AttestationTokenSignature.ps1 -Jwt '%s'\n", jwtToken))
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	// 4. 执行命令并捕获输出
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("error running PowerShell command: %v\nstderr: %s", err, errOut.String())
	}

	// 5. 恢复原工作目录
	if err := os.Chdir(currentDir); err != nil {
		return false, fmt.Errorf("failed to restore original working directory: %v", err)
	}

	// 6. 检查输出
	output := out.String()
	fmt.Println("PowerShell Output:", output)
	if strings.Contains(output, "Hash result: True") {
		return true, nil
	}

	return false, nil

}

func validateJWT(jwtToken string) (bool, error) {
	// 1. 分割 JWT 令牌
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return false, errors.New("invalid JWT format")
	}
	header, payload, signature := parts[0], parts[1], parts[2]

	// 2. 解码 header 和 payload
	headerDecoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return false, fmt.Errorf("failed to decode header: %v", err)

	}
	payloadDecoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false, fmt.Errorf("failed to decode payload: %v", err)
	}

	var headerMap map[string]interface{}
	if err := json.Unmarshal(headerDecoded, &headerMap); err != nil {
		return false, fmt.Errorf("failed to unmarshal header: %v", err)
	}
	/*Header should be like this:
	 {
		"alg": "RS256",
		"jku": "https://sharedeus2.eus2.attest.azure.net/certs",
		"kid": "J0pAPdfXXHqWWimgrH853wMIdh5/fLe1z6uSXYPXCa0=",
		"typ": "JWT"
	  } */

	var payloadMap map[string]interface{}
	if err := json.Unmarshal(payloadDecoded, &payloadMap); err != nil {
		return false, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	// 3. 获取 jku 和 kid
	jku, ok := headerMap["jku"].(string)
	if !ok {
		return false, errors.New("missing or invalid 'jku' field")
	}
	kid, ok := headerMap["kid"].(string)
	if !ok {
		return false, errors.New("missing or invalid 'kid' field")
	}
	fmt.Println("kid:", kid)

	// 4. 从 jku URI 获取证书
	resp, err := http.Get(jku)
	if err != nil {
		return false, fmt.Errorf("failed to fetch certificates from jku: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %v", err)
	}

	var keys struct {
		Keys []struct {
			Alg string   `json:"alg"` // 算法
			Kty string   `json:"kty"` // 密钥类型
			Use string   `json:"use"` // 用途
			Kid string   `json:"kid"` // 密钥 ID
			X5c []string `json:"x5c"` // 证书链
			N   string   `json:"n"`   // RSA 公钥模数
			E   string   `json:"e"`   // RSA 公钥指数
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &keys); err != nil {
		return false, fmt.Errorf("failed to unmarshal keys: %v", err)
	}

	// 5. 找到匹配的证书
	var certChain []string
	for _, key := range keys.Keys {
		if key.Kid == kid {
			certChain = key.X5c
			break
		}
	}
	if len(certChain) == 0 {
		return false, errors.New("no matching certificate found for 'kid'")
	}
	fmt.Println("Cert Chain length:", len(certChain)) //数组长？是1
	fmt.Println("Cert Chain:", certChain)             //字符串

	// 6. 解码证书链
	certs := make([]*x509.Certificate, len(certChain))
	for i, certBase64 := range certChain {
		//check? X.509 certificate usually used standard base64 encoding
		//is certBytes der format
		certBytes, err := base64.StdEncoding.DecodeString(certBase64)
		if err != nil {
			return false, fmt.Errorf("failed to decode certificate: %v", err)
		}
		fmt.Println("base64.StdEncoding.DecodeString, the certBytes: ", certBytes)
		//check certBytes is der format
		block, _ := pem.Decode(certBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			return false, errors.New("failed to parse PEM block containing certificate")
		} //the origin is per format
		// cert, err := x509.ParseCertificate(certBytes) //input shuold be der format cert in bytes

		//test:打印‘标准’PEM DER 格式证书？
		pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
		fmt.Printf("PEM Certificate:\n%s\n", string(pemCert))
		fmt.Printf("DER Certificate:\n%x\n", block.Bytes)

		cert, err := x509.ParseCertificate(block.Bytes)
		fmt.Printf("x509.ParseCertificatecert: %v\n", cert)
		fmt.Println()

		if err != nil {
			return false, fmt.Errorf("failed to parse certificate: %v", err)
		}
		certs[i] = cert
	}

	// 7. 获取签名算法
	alg, ok := headerMap["alg"].(string)
	if !ok {
		return false, errors.New("missing or invalid 'alg' field")
	}
	signatureAlgorithm, ok := algToSignatureAlgorithm[alg]
	if !ok {
		return false, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	// 8. 验证签名
	tokenToVerify := header + "." + payload
	//JWT signature usually use base64url encoding
	signatureDecoded, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %v", err)
	}

	hashed := crypto.SHA256.New()
	hashed.Write([]byte(tokenToVerify))
	digest := hashed.Sum(nil)

	if err := certs[0].CheckSignature(signatureAlgorithm, digest, signatureDecoded); err != nil {
		return false, fmt.Errorf("invalid signature: %v", err)
	}

	return true, nil
}
