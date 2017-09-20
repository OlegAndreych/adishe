package main

import (
	"gopkg.in/routeros.v2"

	"bufio"
	"net/http"
	"strings"

	"github.com/deckarep/golang-set"

	"fmt"
	"io/ioutil"

	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"

	"flag"
	"strconv"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("adishe")
var address = flag.String("addr", "192.168.0.1", "router's address;")
var apiPort = flag.Int("ap", 8728, "api port;")
var login = flag.String("l", "", "login;")
var password = flag.String("p", "", "password;")

func main() {
	prepareLog()
	flag.Parse()
	client := connectToMtk()
	defer client.Close()

	routerRes := make(chan map[string]string, 1)
	go retrieveRouterData(routerRes, client)

	remoteRes := make(chan *mapset.Set, 1)
	go retrieveRemoteData(remoteRes)

	routerMap := <-routerRes
	routerSet := mapset.NewThreadUnsafeSet()
	for key := range routerMap {
		routerSet.Add(key)
	}

	remoteSet := <-remoteRes

	setToAdd := (*remoteSet).Difference(routerSet)
	log.Info("Records to add amount:", setToAdd.Cardinality())
	log.Debug("Set to add:", setToAdd)
	setToDelete := routerSet.Difference(*remoteSet)
	log.Info("Records to delete amount:", setToDelete.Cardinality())
	log.Info("Set to delete:", setToDelete)

	delChan := make(chan bool, 1)
	if setToDelete.Cardinality() > 0 {
		go removeObsoleteRecords(delChan, &setToDelete, routerMap, client)
	} else {
		delChan <- true
	}

	for _, address := range setToAdd.ToSlice() {
		client.Run("/ip/firewall/address-list/add", fmt.Sprintf("=address=%v", address), "=list=adishe")
	}

	log.Info("All records have been imported.")
}

//Prepares log facility.
func prepareLog() {
	backend, err := logging.NewSyslogBackend("adishe")
	if err != nil {
		panic(err)
	}
	logging.SetBackend(backend)
}

// Establishes connection with Mikrotik router.
func connectToMtk() *routeros.Client {
	log.Info("Connecting to Mikrotik.")
	client, err := routeros.Dial(*address+":"+strconv.Itoa(*apiPort), *login, *password)
	if err != nil {
		log.Critical(err)
		panic(err)
	}
	log.Info("Connection to Mikrotik has been established successfully.")
	return client
}

// Retrieves router's static DNS table.
func retrieveRouterData(ch chan map[string]string, client *routeros.Client) {
	log.Info("Retrieving router's static DNS entries.")
	res, err := client.Run("/ip/firewall/address-list/print", "?dynamic=false", "=.proplist=.id,address")
	if err != nil {
		log.Critical(err)
		panic(err)
	}

	routerMap := make(map[string]string)
	for _, val := range res.Re {
		vMap := val.Map
		routerMap[vMap["name"]] = vMap[".id"]
	}

	ch <- routerMap
	log.Info("Router's static DNS entries has been retrieved.")
}

// Retrieves hostnames for blocking.
func retrieveRemoteData(ch chan *mapset.Set) {
	log.Info("Retrieving remote data.")
	resp, err := http.Get("https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts")
	if err != nil {
		log.Critical(err)
		panic(err)
	}
	defer resp.Body.Close()

	domains := mapset.NewThreadUnsafeSet()
	scnr := bufio.NewScanner(resp.Body)
	for act := false; scnr.Scan(); {
		text := scnr.Text()
		if !act {
			act = text == "# End of custom host records."
			continue
		}
		text = strings.Split(text, "#")[0]
		text = strings.TrimSpace(text)
		if len(text) > 0 && !strings.HasPrefix(text, "#") {
			domains.Add(strings.Replace(text, "0.0.0.0 ", "", -1))
		}
	}
	if err := scnr.Err(); err != nil {
		log.Critical(err)
		panic(err)
	}

	ch <- &domains
	log.Info("Remote data has been retrieved.")
}

// Remove outdated static DNS records from Mikrotik
func removeObsoleteRecords(delChan chan bool, setToDeletePtr *mapset.Set, routerMap map[string]string, client *routeros.Client) {
	log.Info("Removing obsolete records from router.")
	setToDelete := *setToDeletePtr
	if setToDelete.Cardinality() > 0 {
		idsToDelete := make([]string, setToDelete.Cardinality())
		for i, val := range setToDelete.ToSlice() {
			idsToDelete[i] = routerMap[val.(string)]
		}
		res, err := client.Run("/ip/firewall/address-list/remove", "?numbers="+strings.Join(idsToDelete, ","))
		if err != nil {
			log.Critical(err)
			panic(err)
		}
		fmt.Println(res)
	}
	delChan <- true
}

// Create script file for import.
func createScriptFile(tempFilenameChan chan string, setToAdd mapset.Set) {
	scriptFile, err := ioutil.TempFile("", "")
	if err != nil {
		log.Critical(err)
		panic(err)
	}
	defer func() {
		scriptFile.Close()
	}()

	scriptWriter := bufio.NewWriter(scriptFile)
	scriptWriter.WriteString("/ip dns static\n")

	for _, val := range setToAdd.ToSlice() {
		scriptWriter.WriteString(fmt.Sprintf("add address=127.0.0.1 name=%s comment=adishe\n", val))
	}

	scriptWriter.Flush()
	tempFilenameChan <- scriptFile.Name()
	log.Info("Obsolete records has been removed from router.")
}

// Uploads script via established ssh session.
func uploadScript(scriptFilename string, scriptFilenameBase string, session *ssh.Session, uploadChan chan bool) {
	log.Info("Uploading script.")
	err := scp.CopyPath(scriptFilename, scriptFilenameBase, session)
	if err != nil {
		log.Critical(err)
		panic(err)
	}
	uploadChan <- true
	log.Info("Script has been uploaded.")
}
