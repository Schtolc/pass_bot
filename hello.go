package main

import "bytes"
import "net/http"
import "flag"
import "encoding/json"
import "github.com/golang/glog"
import "os"
import "golang.org/x/crypto/openpgp"
import "io/ioutil"

const g_token = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
const g_my_id = 243842689
const g_chat_id = 243842689
const pass_path = "/home/pgolubev/.password-store/"

type from struct {
	Id        int    `json:"id"`
	FirstName string `json:"first_name"`
}

type chat struct {
	Id        int    `json:"id"`
	FirstName string `json:"first_name"`
	Type      string `json:"type"`
}

type entities struct {
	Type   string `json:"type"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

type message struct {
	MessageId int        `json:"message_id"`
	From      from       `json:"from"`
	Chat      chat       `json:"chat"`
	Date      int        `json:"date"`
	Text      string     `json:"text"`
	Entities  []entities `json:"entities"`
}

type result struct {
	UpdateId int     `json:"update_id"`
	Message  message `json:"message"`
}

type Update struct {
	Ok     bool     `json:"ok"`
	Result []result `json:"result"`
}

type PassMsgResult struct {
	Ok     bool   `json:"ok"`
	Result result `json:"result"`
}

type PassMsg struct {
	ChatId int    `json:"chat_id"`
	Text   string `json:"text"`
}

var g_last_upd int = 0

func sendMessage(msg string) {
	const send_url = "https://api.telegram.org/bot" + g_token + "/sendMessage"

	passMsg := &PassMsg{ChatId: g_chat_id, Text: msg}
	j, err := json.Marshal(passMsg)
	if err != nil {
		glog.Errorf("sendMessage: [err: %v]", err)
	}

	resp, err := http.Post(send_url, "application/json", bytes.NewBuffer(j))
	if err != nil {
		glog.Errorf("sendMessage: [msg: %v][err: %v]", j, err)
	}

	decoder := json.NewDecoder(resp.Body)
	var res PassMsgResult
	err = decoder.Decode(&res)
	if err != nil || !res.Ok {
		glog.Errorf("sendMessage: [res: %v][err: %v]", res, err)
		return
	}

	glog.Infof("sendMessage: [msg: %s]", msg)
}

func listPasswords() {
	var res string

	files, err := ioutil.ReadDir(pass_path)
	if err != nil {
		glog.Errorf("listPasswords: [err: %v]", err)
	}

	for _, f := range files {
		cur_dir := f.Name()
		if cur_dir[0] != '.' {
			passes, err := ioutil.ReadDir(pass_path + cur_dir)
			if err != nil {
				glog.Errorf("listPasswords: [err: %v]", err)
			}

			for _, f := range passes {
				sz := len(f.Name())
				res += cur_dir + "/" + f.Name()[:sz-4] + "\n***\n"
			}
		}
	}

	sendMessage(res)
}

func getPassword(name string) (string, error) {
	const secretKeyring = "/home/pgolubev/.gnupg/secring.gpg"

	encFile := pass_path + name + ".gpg"
	encBytes, err := ioutil.ReadFile(encFile)
	if err != nil {
		return "", err
	}

	keyringFileBuffer, err := os.Open(secretKeyring)
	if err != nil {
		return "", err

	}
	defer keyringFileBuffer.Close()

	entityList, err := openpgp.ReadKeyRing(keyringFileBuffer)
	if err != nil {
		return "", err

	}
	entity := entityList[0]

	passphraseByte := []byte("XXXXXXXX")
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}

	md, err := openpgp.ReadMessage(bytes.NewBuffer(encBytes), entityList, nil, nil)
	if err != nil {
		return "", err
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

func processMsg(msg string) {
	if msg == "pass" {
		listPasswords()
		return
	}

	pass, err := getPassword(msg)
	if err != nil {
		glog.Errorf("getPassword: [msg: %s][err: %v]", msg, err)
		return
	}

	glog.Infof("getPassword: success [msg: %s]", msg)
	sendMessage(pass)
}

func getUpdates() {
	const update_url = "https://api.telegram.org/bot" + g_token + "/getUpdates"
	resp, err := http.Get(update_url)
	if err != nil {
		glog.Errorf("getUpdate: [err: %v]", err)
		return
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	var upd Update
	err = decoder.Decode(&upd)
	if err != nil {
		glog.Errorf("getUpdate: [err: %v]", err)
		return
	}

	for _, result := range upd.Result {
		if result.UpdateId > g_last_upd {
			g_last_upd = result.UpdateId
			glog.Infof("getUpdate: [message: %s][from: %d]", result.Message.Text, result.Message.From.Id)
			if result.Message.From.Id == 243842689 {
				processMsg(result.Message.Text)
			}
		}
	}
}

func main() {
	flag.Parse()
	glog.Info("Bot started")
	for {
		getUpdates()
	}
}
