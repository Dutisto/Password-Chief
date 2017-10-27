package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strings"
	"hash/fnv"
	"io"
	"path/filepath"
	"crypto/aes"
    	"crypto/md5"
        "crypto/cipher"
        "crypto/rand"
        "encoding/base64"
        "errors"
        "io/ioutil"
       "log"
)

func main(){
	fmt.Print("\n========== Password Chief ==========\n\n")
	usr, _ := user.Current()
	dir := usr.HomeDir
	path := filepath.Join(dir, "password-Chief/")
	if _, err := os.Stat(path); os.IsNotExist(err) {
    os.Mkdir(path, 0777)
}
	reader := bufio.NewReader(os.Stdin)

	//While we don't have a valid answer, we keep asking

	var vchoice = 1
	for vchoice > 0 {
		fmt.Print("(1) Use an existing account \n")
		fmt.Print("(2) Create a new account \n")

		text, _ := reader.ReadString('\n')
		text = strings.Replace(text, "\n", "", -1)
		if text == "1" || text == "2" {
			if text == "2" {

		//Get the logins for the new profile

				fmt.Print("New Username : \n")
				nUser, _ := reader.ReadString('\n')
				nUser = strings.Replace(nUser, "\n", "", -1)
				verif := 1
				for verif > 0{

					fmt.Print("Password : \n")
					nPass1, _ := reader.ReadString('\n')
					nPass1 = strings.Replace(nPass1, "\n", "", -1)
					fmt.Print("Retape your password : \n")
					nPass2, _ := reader.ReadString('\n')
					nPass2 = strings.Replace(nPass2, "\n", "", -1)
					if nPass1 == nPass2 {
						add_user(nUser, nPass1, path)
						verif = -1
					}else{
						fmt.Print("Your passwords doesn't match !\n")
					}
				}

				vchoice = -1
			}else{
				vchoice = -1
		}
			}else{
			fmt.Print("Wrong choice !\n")

		}
	}
	//Login phase
	var user string
	var pass string
	var vuser = 1
	for vuser > 0 {

		fmt.Print("Username : \n")
		user, _ = reader.ReadString('\n')
		user = strings.Replace(user, "\n", "", -1)
		if valideacc(user, path) == false {
			fmt.Print("Username invalid, try again \n")
		}else {
			vuser = -1
		}
	}

	var vpass = 1
	for vpass > 0 {
		fmt.Print("Password : \n")
		pass, _ = reader.ReadString('\n')
		pass = strings.Replace(pass, "\n", "", -1)
		if verify_pass(user, pass, path) == false {
		fmt.Print("Wrong password, try again \n")
		}else {
			vpass = -1
		}
	}
	//User got the choice to add logins, display the file or leave the application
	var dChoice = 1
	for dChoice > 0 {
		fmt.Print("\n(1) Add login:password \n")
		fmt.Print("(2) Display the content of your file \n")
		fmt.Print("(3) Quit Password-Chief \n\n")

		response, _ := reader.ReadString('\n')
		response = strings.Replace(response, "\n", "", -1)
		if response == "1" {
			fmt.Print("Username to add : \n")
			lUser, _ := reader.ReadString('\n')
			lUser = strings.Replace(lUser, "\n", "", -1)
			fmt.Print("Password to add : \n")
			lPass, _ := reader.ReadString('\n')
			lPass = strings.Replace(lPass, "\n", "", -1)
			add_login(user, pass, lUser, lPass, path)
		}else if response  == "2" {
				printContent(user, pass, path)
		}else if response == "3"{
			fmt.Print("Good-Bye ! \n")
			dChoice = -1
		}else{
			fmt.Print("Wrong choice !\n")

		}
	}
}


func verify_pass(user string, pass string, path string) bool{

	//hash the given password

	h := md5.New()
	io.WriteString(h, pass)
	Hpass := h.Sum(nil)

	//Retrieve the content of the user's file, and try decrypting it with the password previously hashed

	etext, _ := ioutil.ReadFile(path+user+".txt")
	dtext, _ := decrypt(Hpass, etext)
	non := string(dtext)
	scanner := bufio.NewScanner(strings.NewReader(non))
	for scanner.Scan() {
	    lineStr := scanner.Text()

	//If we retrieve the chain, password is correct

		if string(lineStr) == "valid_password"{
			return true
		}
	}
	return false
}

func printContent(user string, pass string, path string) int{
	h := md5.New()
	io.WriteString(h, pass)
	Hpass := h.Sum(nil)

	//Once the password hashed, retrieve the content of the file, decrypt it with the password, then display all the content, except "valid_passord"

	etext, _ := ioutil.ReadFile(path+user+".txt")
	dtext, err := decrypt(Hpass, etext)
	if err != nil {
		panic(err)
    	}
	non := string(dtext)
	scanner := bufio.NewScanner(strings.NewReader(non))
	for scanner.Scan() {
	    lineStr := scanner.Text()

		if string(lineStr) != "valid_password"{
			fmt.Print(lineStr)
			fmt.Print("\n")
		}

	}
	return 0
}




func valideacc(user string, path string) bool{

	//An user exist only if there is a .txt file with his name

	if _, err := os.Stat(path+user+".txt"); err == nil {
		return true
	}else {
		return false
	}
}

func add_user(user string, pass string, path string) int{

	//Create an user, create his file, put the chain in and crypt with the hashed password
	fileHandle, _ := os.Create(path+"/"+user+".txt")
	fileHandle.Close()
	h := md5.New()
	io.WriteString(h, pass)
	Hpass := h.Sum(nil)
	etext := []byte("valid_password\n")
	crypt, _ := encrypt(Hpass, etext)
	ioutil.WriteFile(path+user+".txt", crypt, 0777)
	fmt.Println("User added")
	return 0

}

func hash(s string) uint32 {

	//password's MD5

	h := fnv.New32a()
        h.Write([]byte(s))
        return h.Sum32()
}

func encrypt(key, text []byte) ([]byte, error) {

	//Encrypt in aes, with the hashed password and a type []byte variable

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    b := base64.StdEncoding.EncodeToString(text)
    ciphertext := make([]byte, aes.BlockSize+len(b))
    iv := ciphertext[:aes.BlockSize]
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }
    cfb := cipher.NewCFBEncrypter(block, iv)
    cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
    return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {

	//Same as encrypt(), but in the other way. If text is shorter than BlockSize(16), can't decrypt

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    if len(text) < aes.BlockSize {
        return nil, errors.New("ciphertext too short")
    }
    iv := text[:aes.BlockSize]
    text = text[aes.BlockSize:]
    cfb := cipher.NewCFBDecrypter(block, iv)
    cfb.XORKeyStream(text, text)
    data, err := base64.StdEncoding.DecodeString(string(text))
    if err != nil {
        return nil, err
    }
    return data, nil
}
func add_login(user string, pass string, login string, lpass string, path string) {


	//Hash the password, open user's file, decrypt everything, add login:pass, encrypt everything and overwrite the file

	h := md5.New()
	io.WriteString(h, pass)
	key := h.Sum(nil)
	previous, _ := ioutil.ReadFile(path+user+".txt")
	result, err := decrypt(key, previous)
	    if err != nil {
		log.Fatal(err)
	    }

	plaintext := []byte(login+":"+lpass+"\n")
	oui := append(result, plaintext ...)
	ciphertext, err := encrypt(key, oui)
	if err != nil {
		log.Fatal(err)
	    }

	ioutil.WriteFile(path+user+".txt", ciphertext, 0644)

	fmt.Println("Login added to file")

}
