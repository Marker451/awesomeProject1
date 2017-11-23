package main

import(
	"awesomeProject1/keystore"
	"log"
	"time"
	"io/ioutil"
	"encoding/json"
	"github.com/pborman/uuid"
	"encoding/hex"
	"bytes"
	"github.com/ethereum/go-ethereum/crypto"
)
var pwdfile string = "./passwords"

func readPWDFile()([]byte, error){
	data, err := ioutil.ReadFile(pwdfile)
	if err != nil {
		return nil, err
	}
	return data, nil

}
func main(){
	auth := "123"
	/*
	data, err := readPWDFile()
	if err != nil {
		log.Println("read pwdfile err ",err)
		return
	}

	reader := bufio.NewReaderSize(bytes.NewReader(data),4096)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			log.Println(err)
			return
		}
		log.Println(string(line))
	}

	return
	*/
	keyjson, err := ioutil.ReadFile("./UTC")
	if err != nil {
		log.Println(err)
	}
/*
	ppKey, _ := keystore.GetKey(keyjson, auth)
	log.Printf("%x",ppKey.Address)
	log.Println(address)
	return
*/


	k := keystore.GetencryptedKeyJSONV3()
	if err := json.Unmarshal(keyjson, k); err != nil {
		log.Println(err)
	}
	//////////
	var (
		keyBytes, keyId []byte
	)

	keyProtected := k

	keyId = uuid.Parse(keyProtected.Id)
	mac, err := hex.DecodeString(keyProtected.Crypto.MAC)
	if err != nil {
		log.Println(err)
	}

	iv, err := hex.DecodeString(keyProtected.Crypto.CipherParams.IV)
	if err != nil {
		log.Println(err)
	}

	cipherText, err := hex.DecodeString(keyProtected.Crypto.CipherText)
	if err != nil {
		log.Println(err)
	}




	start := time.Now()
	for index := 0; index < 2; index++ {
		go func(k int) {
			for i := 0; i < 1000; i++ {
				derivedKey, err := keystore.GetKDFKey(keyProtected.Crypto, auth)
				if err != nil {
					log.Println(err)
					continue
				}

				calculatedMAC := crypto.Keccak256(derivedKey[16:32], cipherText)
				if !bytes.Equal(calculatedMAC, mac) {
					//log.Println("false")
					continue
				}

				plainText, err := keystore.AesCTRXOR(derivedKey[:16], cipherText, iv)
				if err != nil {
					//log.Println(err)
					continue
				}

				///////
				keyBytes = plainText
				key := crypto.ToECDSAUnsafe(keyBytes)

				pKey := keystore.Key{
					Id:         uuid.UUID(keyId),
					Address:    crypto.PubkeyToAddress(key.PublicKey),
					PrivateKey: key,
				}
				log.Printf("%+v", pKey)
				log.Printf("%x", pKey.Address)

			}
			log.Println(k, time.Since(start))
		}(index)
	}

	time.Sleep(time.Minute * 10)



}

func tryDecode(count int){

}


//OTCwallet
/*
import (
	"log"
	"io/ioutil"
	"net/http"
	"encoding/json"
)
type PostContent struct {
	Jsonrpc string   `json:"jsonrpc"`
	Method  string   `json:"method"`
	Params  []string `json:"params"`
	ID      int      `json:"id"`
}

func HandleAll(w http.ResponseWriter, req *http.Request){
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Println(err)
	}
	log.Println(string(body))
	post := &PostContent{}
	err = json.Unmarshal(body,post)
	if err != nil {
		log.Println(err)
	}
	w.Header().Set("Content-Type","text/plain")
	switch post.Method {
		case "eth_getBalance":
			w.Write([]byte(`{"jsonrpc": "2.0","id":1,"result": "0x9ab860d3b82d380000000"}`))
			return
		case "eth_getTransactionCount":
			w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xa"}`))
			return
		case "eth_sendRawTransaction":
			w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":"0xee2d6addf60a15eee0be0d93af7d6457e6f9b6c2d5f804b82e582b801e3e4521"}`))
			return
	}

}

func main() {
	http.HandleFunc("/", HandleAll)
	err := http.ListenAndServeTLS(":443","./cert.pem", "./key.pem", nil)
	if err != nil {
		log.Println(err)
	}
}
*/

//读取其他目录数据 windows
/*
func main(){
	filePath := "C:\\Users\\sanceng\\AppData\\Roaming\\OTCWalletData\\peerIp"
	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Println(err)
	}
	log.Println(string(file))
	time.Sleep(time.Second * 100)

}
*/
