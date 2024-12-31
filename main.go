package main

import (
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
	// "github.com/zzGHzz/tls-node/comm"
)

const (
	address       = "0.0.0.0:8072" //"localhost:8072"
	nonceServer   = "1P6*&%4u#w$M"
	serverCreDir  = "./script/server-cred"      //folder path to read server credentials(certs)
	clientCredDir = "./script/client-cred-recv" //folder path to store client credentials(certs)
	mma_path      = "./script/mma_config.json"  //tdx mma config file
	psh_script    = "./script"
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
	//1.server establish socket with client (ip:localhost, port:8072)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	defer listener.Close()
	fmt.Println("Server listening on", address)

	conn, err := listener.Accept()
	if err != nil {
		fmt.Println("Error accepting connection:", err)
		return
	}
	defer conn.Close()

	//2.server send 3 files: nonce(12-byte length in string format), node0-ca.crt, node0-server.crt
	//2.1 Access these file. The directory path of all these files located：./script/server-cred
	//2.2 Sent to the client;
	sendMessage(conn, nonceServer)
	sendFile(conn, serverCreDir+"/node0-ca.crt")
	sendFile(conn, serverCreDir+"/node0-server.crt")

	//3. receive client nonce, node1-ca.crt, node1-client.crt; And store them in "./script/client-cred-recv" folder
	clientNonce := receiveMessage(conn)
	fmt.Println("Client Nonce:", clientNonce)
	// saveFile(clientNonce, clientCredDir+"/nonce.txt")
	receiveFile(conn, clientCredDir+"/node1-ca.crt")
	receiveFile(conn, clientCredDir+"/node1-client.crt")

	//4. call the system tool and obtain the return result, stored in JWTResult;
	//4.1 Command to call the "AttestationClient": sudo AttestationClient -n "nonce" -o token
	extractPubkey := callOpensslGetPubkey(serverCreDir + "/node0-server.crt")
	fmt.Print("Extracted pubkey test1:", extractPubkey)
	extractPubkey = extractPubkeyFromPem(extractPubkey)

	machineName, err := os.Hostname()
	fmt.Println("Machine Name:", machineName)
	jwtResult := ""
	if err != nil {
		fmt.Println("Error getting machine name:", err)
		return
	}
	if strings.Contains(strings.ToUpper(machineName), "SNP") {
		fmt.Println("callSNPAttestationClient")
		jwtResult = callSNPAttestationClient(clientNonce + extractPubkey)

	} else if strings.Contains(strings.ToUpper(machineName), "TDX") {
		fmt.Println("callTDXAttestationClient")
		jwtResult = callTDXAttestationClient(clientNonce+extractPubkey, mma_path)
	} else {
		fmt.Println("Unsupported machine type")
		return
	}

	//5. server send JWTResult to client
	fmt.Println("Send self JWT Result:", jwtResult)
	sendMessage(conn, jwtResult)

	//6. receive client JWTResult and print it
	clientJwtResult := receiveMessage(conn)
	fmt.Println("Recv Client JWT Result:", clientJwtResult)

	//7. validate client JWTResult
	isValid, err := validateJWTwithPSH(clientJwtResult)
	if err != nil {
		fmt.Println("Error validating JWT:", err)
	} else {
		fmt.Println("JWT Validation Result:", isValid)
	}

	//8. Check the JWT token claims
	expectPubkey := callOpensslGetPubkey(clientCredDir + "/node1-client.crt")
	expectPubkey = extractPubkeyFromPem(expectPubkey)
	expectUserData := calExptUserData(clientCredDir + "/node1-client.crt")
	checkTee, checkPubkey, checkNonce, checkUserData, err := extractAndCheckJWTCliams(clientJwtResult, expectPubkey, nonceServer, expectUserData) //client check Server's JWT claims,should be the clientNonce
	if err != nil {
		fmt.Println("Error checking JWT claims:", err)
	} else {
		if checkNonce && checkPubkey && checkTee && checkUserData {
			fmt.Println("Vlidation of JWT Claims passed")
		} else {
			fmt.Println("Vlidation of JWT Claims failed")
		}
	}

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
	// 先读取长度
	lengthBuf := make([]byte, 2) // 假定长度不会超过16字节
	conn.Read(lengthBuf)

	length := int(lengthBuf[0])<<8 | int(lengthBuf[1])

	// 读取消息内容
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
	// 先读取文件长度
	buf := make([]byte, 4)
	conn.Read(buf)
	length := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	data := make([]byte, length)
	conn.Read(data)
	ioutil.WriteFile(filePath, data, 0644)
}

/* Read the pubkey from the pem.file in certain format */
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

/* Call openssl to get the pubkey from the certificate */
func callOpensslGetPubkey(filePath string) string {
	cmd := exec.Command("openssl", "x509", "-in", filePath, "-pubkey", "-noout")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error getting pubkey from certificate", err)
		return ""
	}
	return string(output)
}

/* to get SNP machine attestation JWT */
func callSNPAttestationClient(nonce string) string {
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

/* to get TDX machine attestation JWT */
func callTDXAttestationClient(nonce string, mma_path string) string {
	nonce = ""
	cmd := exec.Command("sudo", "TdxAttest", "-c", mma_path)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error calling AttestationClient:", err)
		return ""
	}

	oriOut := string(output)
	startIndex := strings.Index(oriOut, "eyJhb")
	extractedToken := ""
	if startIndex != -1 {
		// 提取从 "eyJhb" 开始到字符串末尾的内容
		extractedToken = oriOut[startIndex:]
		extractedToken = strings.TrimSpace(extractedToken)
		fmt.Println("Extracted JWT Token:")
		fmt.Println(extractedToken)
	} else {
		fmt.Println("JWT Token not found.")
	}
	return extractedToken
}

/* validate MAA JWT  */
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

// func isValidJwt(token string) bool {
// 	// Implementation of JWT validation logic
// 	return true // Placeholder return
// }

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

/* depracated */
func extractAndCheckJWTCliamsSNP_Multiplex(jwtToken, exptPubKey, exptNonce string) (bool, bool, bool, error) {
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
	// fmt.Print("Expected Pubkey:", exptPubKey)
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

/* extract and check these JWT claims */
func extractAndCheckJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData string) (bool, bool, bool, bool, error) {
	teeType, err := getPeerTeeType(jwtToken)
	if err != nil {
		fmt.Print("getPeerTeeType failed:", teeType)
		return true, true, true, false, err
	}
	if teeType == "sevsnpvm" {
		return extractAndCheck_SNPJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData)
	}
	if teeType == "tdxvm" {
		return extractAndCheck_TDXJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData)
	}
	return false, false, false, false, fmt.Errorf("unsupported tee type: %s", teeType)
}

/* Currently SNP JWT contains Nonce field */
func extractAndCheck_SNPJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData string) (bool, bool, bool, bool, error) {
	// 1. parse JWT
	token, err := parseJWT(jwtToken)
	if err != nil {
		return false, false, false, false, err
	}

	// 2.  payload中读 x-ms-isolation-tee.x-ms-compliance-status 的值
	teeComplianceStatus, ok := token.Payload["x-ms-isolation-tee"].(map[string]interface{})["x-ms-compliance-status"].(string)
	checkTee := ok && strings.Contains(teeComplianceStatus, "azure-compliant-cvm")

	// 3. payload中读 x-ms-runtime.client-payload.nonce 的值
	clientPayload, ok := token.Payload["x-ms-runtime"].(map[string]interface{})["client-payload"].(map[string]interface{})
	if !ok {
		return false, false, false, false, fmt.Errorf("missing x-ms-runtime.client-payload.nonce in payload")
	}
	noncePubkey, ok := clientPayload["nonce"].(string)
	if !ok {
		return false, false, false, false, fmt.Errorf("missing x-ms-runtime.client-payload.nonce in payload")
	}
	fmt.Println("NoncePubkey:", noncePubkey)
	// 4. 对 noncePubkey 执行 Base64URL decode
	// noncePubkeyDecode, err := base64.RawURLEncoding.DecodeString(noncePubkey)//for non-padding base64url encoding
	noncePubkeyDecode, err := base64.StdEncoding.DecodeString(noncePubkey)

	if err != nil {
		return false, false, false, false, fmt.Errorf("failed to decode noncePubkey: %v", err)
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

	// 5. check user-data field
	// 5.1 read user-data measurement from jwtToken
	userData := ""
	userData, ok = token.Payload["x-ms-isolation-tee"].(map[string]interface{})["x-ms-runtime"].(map[string]interface{})["user-data"].(string)
	if !ok {
		return true, true, true, false, fmt.Errorf("parsing x-ms-isolation-tee.x-ms-runtime.user-data in payload failed")
	}
	exptUserData = strings.ToUpper(exptUserData)
	fmt.Println("UserData measurement:", userData)
	fmt.Println("Expected UserData measurement:", exptUserData)
	checkUserData := exptUserData == userData

	// In test, the userData read from JWT is the same because we are in the same host; but in real env, the userData should be different; The eptUserData is calculated from cert that it is ok
	// remove this line when deploy
	return checkTee, checkPubkey, checkNonce, checkUserData, nil
}

/* Currently TDX JWT contains no Nonce field */
func extractAndCheck_TDXJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData string) (bool, bool, bool, bool, error) {

	// 1. parse JWT
	token, err := parseJWT(jwtToken)
	if err != nil {
		return false, false, false, false, err
	}

	// 2.  payload中读 x-ms-isolation-tee.x-ms-compliance-status 的值
	teeComplianceStatus, ok := token.Payload["x-ms-compliance-status"].(string)
	checkTee := ok && strings.Contains(teeComplianceStatus, "azure-compliant-cvm")
	// thies two fields are not used in TDX JWT claims chcking; simple set them to true
	checkPubkey := true
	checkNonce := true
	fmt.Println("TeeComplianceStatus:", teeComplianceStatus)

	if !checkTee {
		fmt.Println("TeeComplianceStatus is not compliant-cvm")
	}
	if !checkPubkey {
		fmt.Println("Public Key does not match")
	}
	if !checkNonce {
		fmt.Println("Nonce does not match")
	}

	// 5. check user-data field (is the hash of the pubkey)
	// 5.1 read user-data measurement from jwtToken
	userData := ""
	userData, ok = token.Payload["x-ms-runtime"].(map[string]interface{})["user-data"].(string)
	if !ok {
		return true, true, true, false, fmt.Errorf("parsing x-ms-runtime.user-data in payload failed")
	}
	exptUserData = strings.ToUpper(exptUserData)
	fmt.Println("UserData measurement:", userData)
	fmt.Println("Expected UserData measurement:", exptUserData)
	checkUserData := exptUserData == userData
	return checkTee, checkPubkey, checkNonce, checkUserData, nil
}

func getPeerTeeType(jwtToken string) (string, error) {
	// 1. 解析 JWT
	token, err := parseJWT(jwtToken)
	if err != nil {
		return "", err
	}

	// 2. 读取 x-ms-isolation-tee.x-ms-compliance-status 字段
	teeType, ok := token.Payload["x-ms-attestation-type"].(string)
	if !ok {
		return "", errors.New("missing x-ms-attestation-type in payload")
	}

	if teeType != "tdxvm" { //SNP JWT Structure
		teeType, ok = token.Payload["x-ms-isolation-tee"].(map[string]interface{})["x-ms-attestation-type"].(string)
		if !ok {
			return "", errors.New("missing x-ms-isolation-tee.x-ms-attestation-type in payload")
		}
	}
	return teeType, nil
}

/* Calculate the expected value of the user_data */
func calExptUserData(certPath string) string {
	pubkey := callOpensslGetPubkey(certPath)
	pubkey = extractPubkeyFromPem(pubkey)
	fmt.Println("pubkey used in calExptUserData:", pubkey)
	// Create JSON object
	userDataJSON := map[string]string{
		"user_data": pubkey,
	}
	//Marshal the map into JSON bytes
	userDataJSONBytes, err := json.Marshal(userDataJSON)
	if err != nil {
		fmt.Println("Error marshalling user data JSON:", err)
		return ""
	}
	fmt.Println("UserData JSON:", string(userDataJSONBytes))
	//Calculate the SHA512 hash of the JSON string
	hash := sha512.Sum512(userDataJSONBytes)
	hashBytes := hash[:] //Convert [64] byte to []byte
	hashHex := fmt.Sprintf("%x", hashBytes)

	return hashHex
}
