package cmdcap

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	ps "github.com/mitchellh/go-ps"
)

func catch(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func createLogDir(path string) string {
	_, err := os.Stat(path)
	if err != nil {
		err := os.Mkdir(path, 0755)
		catch(err)
	}
	return path
}

func countFiles(path string) int {
	files, err := ioutil.ReadDir(path)
	catch(err)
	return len(files)
}

func fname(path string) string {
	files := countFiles(path)
	filesn := strconv.Itoa(files)
	return path + "log-" + filesn + ".log"
}

func createLogFile(path string) string {
	filename := fname(path)
	file, err := os.Create(filename)
	catch(err)
	defer file.Close()
	return file.Name()
}

func procData() string {
	processData := ""
	currentPid := os.Getpid()
	proc, err := ps.FindProcess(currentPid)
	if err != nil {
		log.Fatal(err)
	}
	pproc, err := ps.FindProcess(proc.PPid())
	if err != nil {
		log.Fatal(err)
	}
	processData = processData + "PP: " + pproc.Executable() + " (" + strconv.Itoa(pproc.Pid()) + "), "
	processData = processData + "P: " + proc.Executable() + " (" + strconv.Itoa(proc.Pid()) + "), "

	return processData
}

func argsToStr(args []string) string {
	str := ""
	for _, arg := range args {
		str = str + arg + " "
	}
	return str
}

func CaptureCmd(path string) {
	cwdPath, err := os.Getwd()

	lastChar := path[len(path)-1:]
	if lastChar != "/" {
		path = path + "/"
	}
	process := procData()
	path = path + "logs/"
	createLogDir(path)
	logFile := createLogFile(path)

	file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE, 0666)
	catch(err)
	defer file.Close()

	argArr := os.Args
	args := argsToStr(argArr)

	logStr := process + "C: \"" + args + "\"" + "path: " + cwdPath

	w := bufio.NewWriter(file)
	fmt.Fprintln(w, logStr)

	w.Flush()
}
