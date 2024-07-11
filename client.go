package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username   string
	Password   []byte
	PrivateRSA userlib.PrivateKeyType
	PrivateSig userlib.PrivateKeyType

	//public: password, RSA/Sig
	//private: UserKey

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

//use RSA to encrypt a symmetric key

func RSAAndSig(class []byte, rsa userlib.PKEEncKey, sig userlib.DSSignKey) (enc_struct []byte, err error) {
	var storage EncryptStruct
	//fmt.Println(len(class))
	e_key := userlib.RandomBytes(16)
	iv := userlib.RandomBytes(16)
	e_encrypt, err := userlib.PKEEnc(rsa, e_key)
	if err != nil {
		//fmt.Println("IT breaks here")
		return nil, err
	}
	e_signed, err := userlib.DSSign(sig, e_encrypt)
	if err != nil {
		//fmt.Println("IT breaks here")
		return nil, err
	}
	storage.Encryption = userlib.SymEnc(e_key, iv, class)
	storage.Key = e_encrypt
	storage.KeyMac = e_signed

	enc_struct, err = json.Marshal(storage)
	if err != nil {
		return nil, err
	}

	return enc_struct, nil
}

func EncryptAndMac(class []byte, encrypt []byte, mac []byte) (enc_struct []byte, err error) {
	var storage EncryptStruct

	if err != nil {
		//fmt.Println("2")
		return nil, err
	}
	encrypted_stuct := userlib.SymEnc(encrypt, userlib.RandomBytes(16), class)
	hmac_struct, err := userlib.HMACEval(mac, encrypted_stuct)
	if err != nil {
		return nil, err
	}
	storage.Encryption = encrypted_stuct
	storage.Hmac = hmac_struct

	enc_struct, err = json.Marshal(storage)

	if err != nil {
		//fmt.Println("1")
		return nil, err
	}
	return enc_struct, nil

}
func RSAAndVerify(j_son []byte, rsa userlib.PKEDecKey, sig userlib.DSVerifyKey) (json_struct []byte, err error) {
	var new_struct EncryptStruct

	err = json.Unmarshal(j_son, &new_struct)
	if err != nil {
		return nil, err
	}

	err = userlib.DSVerify(sig, new_struct.Key, new_struct.KeyMac)
	if err != nil {
		//fmt.Println("3.9")
		return nil, err
	}
	json_struct, err = userlib.PKEDec(rsa, new_struct.Key)
	if err != nil {
		//fmt.Println("3.5")
		return nil, err
	}
	json_struct_new := userlib.SymDec(json_struct, new_struct.Encryption)
	return json_struct_new, nil
}
func DecryptAndVerify(j_son []byte, encrypt []byte, mac []byte) (json_struct []byte, err error) {
	var new_struct EncryptStruct

	err = json.Unmarshal(j_son, &new_struct)

	verifier, err := userlib.HMACEval(mac, new_struct.Encryption)
	if err != nil {
		//fmt.Println("3")
		return nil, err
	}
	if !userlib.HMACEqual(new_struct.Hmac, verifier) {
		return nil, err
	}
	json_struct = userlib.SymDec(encrypt, new_struct.Encryption)
	return json_struct, nil

}

type EncryptStruct struct {
	Encryption []byte
	Hmac       []byte
	Key        []byte
	KeyMac     []byte
}

// Generating userkey
func UserkeyGen(username string, password []byte) (userkey []byte) {
	usercheck, _ := uuid.FromBytes(userlib.Hash([]byte(username[:] + "salt"))[:16])
	usersalt, _ := userlib.DatastoreGet(usercheck)

	hasher := userlib.Hash([]byte(username))
	hasher = append(hasher, userlib.Hash(password)...)
	userkey = userlib.Argon2Key(hasher, usersalt, 16)
	return userkey

}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		return nil, errors.New("login name short")
	}
	usercheck, err := uuid.FromBytes(userlib.Hash([]byte(username[:] + "salt"))[:16])
	_, ok := userlib.DatastoreGet(usercheck)
	if ok {

		return nil, errors.New("User exists")
	}
	//Generating/storing user salt
	usersalt := userlib.RandomBytes(16)
	userlib.DatastoreSet(usercheck, usersalt)

	//Generating/storing signature and RSA keys

	rsapub, rsapriv, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	privsig, pubsig, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	// //fmt.Println()
	// //fmt.Println(username + " Sig PUB")
	// //fmt.Println(pubsig)
	// //fmt.Println()
	// //fmt.Println(username + " Sigpriv ")
	// //fmt.Println(privsig)
	// //fmt.Println()

	userlib.KeystoreSet(username+"_rsa", rsapub)
	userlib.KeystoreSet(username+"_sig", pubsig)

	//Generating PBKDF and map of HKDF keys
	hasher := userlib.Hash([]byte(username))
	hasher = append(hasher, userlib.Hash([]byte(password))...)
	userkey := userlib.Argon2Key(hasher, usersalt, 16)
	toKey := [2]string{"encrypt", "mac"}
	keymap := HashKDFGen(userkey, toKey[:])

	//Assigning to userstruct
	var userdata User
	userdata.Username = username
	userdata.Password = userlib.Hash([]byte(password))
	userdata.PrivateRSA = rsapriv
	userdata.PrivateSig = privsig

	p, err := json.Marshal(userdata)
	if err != nil {
		return nil, err
	}

	user_info, err := EncryptAndMac(p, keymap["encrypt"], keymap["mac"])

	if err != nil {
		//fmt.Println("4")
		return nil, err
	}
	user_uuid, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(user_uuid, user_info)
	return &userdata, nil

	//storing userstruct

}

// Deterministically generate hashKDF keys from PBKDF and purposes
func HashKDFGen(key []byte, purposes []string) (keymap map[string][]byte) {
	keymap = make(map[string][]byte)

	for i := 0; i < len(purposes); i++ {
		item, _ := userlib.HashKDF(key, []byte(purposes[i]))
		keymap[purposes[i]] = item[:16]
	}
	return keymap

}

func GetUser(username string, password string) (userdataptr *User, err error) {

	usercheck, err := uuid.FromBytes(userlib.Hash([]byte(username[:] + "salt"))[:16])
	_, ok := userlib.DatastoreGet(usercheck)
	if !ok {

		return nil, errors.New("User does not exist")
	}
	userUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	userkey := UserkeyGen(username, []byte(password))
	toKey := [2]string{"encrypt", "mac"}
	keymap := HashKDFGen(userkey, toKey[:])
	struct_bytes, ok := userlib.DatastoreGet(userUUID)
	userBytes, err := DecryptAndVerify(struct_bytes, keymap["encrypt"], keymap["mac"])
	if err != nil {
		//fmt.Println("5")
		// flasg
		return nil, err

	}
	var userdata User
	err = json.Unmarshal(userBytes, &userdata)
	if err != nil {
		//fmt.Println("6")
		return nil, err
	}
	return &userdata, nil
}

type OwnerFile struct {
	Ownername []byte
	Filename  []byte
	//Holder
	ShareUUID userlib.UUID
	ShareKey  []byte
	ShareMac  []byte
	//Creator
	FileUUID    userlib.UUID
	EncryptFile []byte
	HMACFile    []byte
	SharedMap   map[string]userlib.UUID
	EncryptMap  map[userlib.UUID][]byte
	HMACMap     map[userlib.UUID][]byte
	//MAKE SURE TO USE STRING of the Hash of USERNAME AS INPUT
	//Below are to unlock shared struct

	//HDKF(userkey, toByte("shared") + toByte("username") + toByte(HMAC/Encryption))
	//stored at username + filename deterministic UUID
	//stores random UUID of all shared structs, and keys
}
type Shared struct {
	Ownername   []byte
	FileUUID    userlib.UUID //stored at random UUID
	EncryptFile []byte
	HMACFile    []byte
	ValidStruct bool

	//holds hash of ownername (only person who can recreate file keys)
	//holds random UUID of file and keys
	//if file gets revoked, through the shared struct of people who still have access, recall storefile on FileStruct and update keys
}
type File struct {
	//stored at random UUID
	//holds counter information (initialized at 1)
	Counter int
	//each counter is FileUUID concacenate with counter

	//below is just for easy access: the same keys that unlock this file unlock the chunks
	FileUUID    userlib.UUID
	EncryptFile []byte
	HMACFile    []byte
}

type FileChunk struct {
	Content []byte
}

//will create top down ownership struct

func (userdata *User) CreateOwner(Ownername string, filename string, myFile bool, content []byte, inviteID userlib.UUID) (err error) {
	var o_struct OwnerFile
	o_struct.Ownername = userlib.Hash([]byte(Ownername))[:16]

	o_struct.Filename = userlib.Hash([]byte(filename))[:16]

	userkey := UserkeyGen(userdata.Username, userdata.Password)
	if myFile {
		fileID, filekey, filemac, err := CreateFile(content)
		if err != nil {
			//fmt.Println("12")
			return nil
		}
		o_struct.FileUUID = fileID
		o_struct.EncryptFile = filekey
		o_struct.HMACFile = filemac
		o_struct.EncryptMap = make(map[uuid.UUID][]byte)
		o_struct.SharedMap = make(map[string]uuid.UUID)
		o_struct.HMACMap = make(map[uuid.UUID][]byte)
	} else {
		theirSig, ok := userlib.KeystoreGet(Ownername + "_sig")
		if !ok {
			return errors.New("No theirsig for " + userdata.Username)
		}

		myRSA := userdata.PrivateRSA
		storedBits, ok := userlib.DatastoreGet(inviteID)
		if !ok {
			return errors.New("No theirsig for " + userdata.Username)
		}
		// //fmt.Println(userdata.Username + " Sigpriv ")
		// //fmt.Println(userdata.PrivateSig)
		// //fmt.Println()
		structbits, err := RSAAndVerify(storedBits, myRSA, theirSig)
		if err != nil {
			return err
		}
		var i Invite
		err = json.Unmarshal(structbits, &i)
		if err != nil {
			return err

		}
		s_bytes, ok, err := getStruct(i.ShareID, i.Sharekey, i.Sharehmac)
		if err != nil {
			return errors.New("Error getting shared struct")

		}
		if !ok {
			return errors.New("Shared struct does not exist")
		}

		s, err := toShare(s_bytes)
		if err != nil {
			return errors.New("Error getting shared struct")

		}
		if !s.ValidStruct {
			return errors.New("Not a valid struct anymore")
		}

		o_struct.ShareUUID = i.ShareID
		o_struct.ShareKey = i.Sharekey
		o_struct.ShareMac = i.Sharehmac
	}

	hasher := userlib.Hash([]byte(userdata.Username))
	hasher = append(hasher, userlib.Hash([]byte(filename))...)
	finalHash := userlib.Hash(hasher)[:16]
	ownerUUID, err := uuid.FromBytes(finalHash)
	if err != nil {
		return err
	}
	toKey := [2]string{"encrypt_ownership", "mac_ownership"}
	keymap := HashKDFGen(userkey, toKey[:])

	p, err := json.Marshal(o_struct)
	user_info, err := EncryptAndMac(p, keymap["encrypt_ownership"], keymap["mac_ownership"])
	if err != nil {
		return err
	}
	userlib.DatastoreSet(ownerUUID, user_info)
	return nil

} /*
func CreateHolder(ownername []byte, username []byte, filename string, content []byte) {
	var h Holder
	h.
}
*/

func CreateFile(content []byte) (fileID userlib.UUID, filekey []byte, filemac []byte, err error) {
	fileID = uuid.New()
	filekey = userlib.RandomBytes(16)
	filemac = userlib.RandomBytes(16)
	var f File
	f.Counter = 1
	f.FileUUID = fileID
	f.EncryptFile = filekey
	f.HMACFile = filemac

	//CreatingFileChunk
	err = CreateFileChunk(f.FileUUID, f.EncryptFile, f.HMACFile, content, f.Counter)
	//fmt.Println(string(content))
	if err != nil {
		//fmt.Println("12.1")
		return uuid.Nil, nil, nil, err
	}
	filedata, err := json.Marshal(f)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	toEncrypt, err := EncryptAndMac(filedata, f.EncryptFile, f.HMACFile)
	if err != nil {
		//fmt.Println("12.2")
		return uuid.Nil, nil, nil, err
	}
	userlib.DatastoreSet(f.FileUUID, toEncrypt)
	return f.FileUUID, f.EncryptFile, f.HMACFile, nil
}
func CreateFileChunk(fileID userlib.UUID, key []byte, mac []byte, content []byte, counter int) (err error) {
	var fc FileChunk
	fc.Content = content

	fcIDbytes := append(fileID[:], byte(counter))
	finalHash := userlib.Hash(fcIDbytes)[:16]
	fc_UUID, err := uuid.FromBytes(finalHash)
	if err != nil {
		return err
	}
	chunkdata, err := json.Marshal(fc)
	if err != nil {
		return err
	}
	toEncrypt, err := EncryptAndMac(chunkdata, key, mac)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fc_UUID, toEncrypt)
	return nil
}
func getStruct(id userlib.UUID, ownerkey []byte, ownermac []byte) (j_son []byte, ok bool, err error) {
	userGet, bool := userlib.DatastoreGet(id)
	if !bool {
		return nil, false, nil
	}
	userBytes, err := DecryptAndVerify(userGet, ownerkey, ownermac)
	if err != nil {
		return nil, false, err
	}
	return userBytes, true, nil

}
func toOwner(item []byte) (ownerPoint *OwnerFile, err error) {
	var o OwnerFile
	json.Unmarshal(item, &o)
	return &o, nil
}
func toShare(item []byte) (sharePoint *Shared, err error) {
	var o Shared
	json.Unmarshal(item, &o)
	return &o, nil
}
func toFile(item []byte) (sharePoint *File, err error) {
	var o File
	json.Unmarshal(item, &o)
	return &o, nil
}
func toChunk(item []byte) (sharePoint *FileChunk, err error) {
	var o FileChunk
	json.Unmarshal(item, &o)
	return &o, nil
}

func (userdata *User) GetFile(filename string) (f *File, ok bool, err error) {
	hasher := userlib.Hash([]byte(userdata.Username))
	hasher = append(hasher, userlib.Hash([]byte(filename))...)
	finalHash := userlib.Hash(hasher)[:16]
	ownerUUID, err := uuid.FromBytes(finalHash)
	if err != nil {
		return nil, false, err
	}
	toKey := [2]string{"encrypt_ownership", "mac_ownership"}
	userkey := UserkeyGen(userdata.Username, userdata.Password)
	keymap := HashKDFGen(userkey, toKey[:])

	userBytes, ok, err := getStruct(ownerUUID, keymap["encrypt_ownership"], keymap["mac_ownership"])
	if !ok {
		return nil, false, errors.New("No such file 1")
	}
	if err != nil {
		////fmt.Println("8")
		return nil, false, err
	}
	userStruct, err := toOwner(userBytes)

	if err != nil {
		////fmt.Println("9")

		return nil, false, err
	}

	userChecker := userlib.Hash([]byte(userdata.Username))[:16]

	if bytes.Equal(userChecker, userStruct.Ownername) {

		item, _, err := getStruct(userStruct.FileUUID, userStruct.EncryptFile, userStruct.HMACFile)
		if err != nil {
			return nil, false, err
		}
		f, err = toFile(item)

	} else {
		var s *Shared
		item, _, err := getStruct(userStruct.ShareUUID, userStruct.ShareKey, userStruct.ShareMac)
		if err != nil {

			return nil, false, err
		}
		s, err = toShare(item)
		////fmt.Println(userdata.Username + "ID")
		////fmt.Println(s.FileUUID)
		newItem, ok, err := getStruct(s.FileUUID, s.EncryptFile, s.HMACFile)
		if !ok {
			return nil, ok, errors.New("random")
		}
		if err != nil {
			return nil, false, err
		}
		f, err = toFile(newItem)
	}
	return f, true, nil

}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	hasher := userlib.Hash([]byte(userdata.Username))
	hasher = append(hasher, userlib.Hash([]byte(filename))...)
	finalHash := userlib.Hash(hasher)[:16]
	ownerUUID, err := uuid.FromBytes(finalHash)
	if err != nil {
		return err
	}
	toKey := [2]string{"encrypt_ownership", "mac_ownership"}
	userkey := UserkeyGen(userdata.Username, userdata.Password)
	keymap := HashKDFGen(userkey, toKey[:])

	userBytes, bool, err := getStruct(ownerUUID, keymap["encrypt_ownership"], keymap["mac_ownership"])
	if err != nil {
		return err
	}
	if !bool {

		err = userdata.CreateOwner(userdata.Username, filename, true, content, uuid.Nil)
		if err != nil {
			return err
		}
		return nil
	} else {
		userStruct, err := toOwner(userBytes)
		if err != nil {
			return err
		}
		userChecker := userlib.Hash([]byte(userdata.Username))[:16]
		var f *File
		if bytes.Equal(userChecker, userStruct.Ownername) {
			item, _, err := getStruct(userStruct.FileUUID, userStruct.EncryptFile, userStruct.HMACFile)
			if err != nil {
				return err
			}
			f, err = toFile(item)

		} else {
			var s *Shared
			item, ok, err := getStruct(userStruct.ShareUUID, userStruct.ShareKey, userStruct.ShareMac)
			if !ok {
				return errors.New("random")
			}
			if err != nil {
				return err
			}
			s, err = toShare(item)
			newItem, ok, err := getStruct(s.FileUUID, s.EncryptFile, s.HMACFile)
			if !ok {
				return errors.New("wrong")
			}
			if err != nil {
				return err
			}
			f, err = toFile(newItem)
		}
		amt := len(content)

		contentPerC := float64(amt / f.Counter)

		contentPerCounter := int(float64(contentPerC)) + 1
		newCounter := 1
		first := int(0)
		second := int(0)
		for amt > second {
			holder := first + contentPerCounter

			if amt < holder {
				second = amt
			} else {
				second = holder

			}

			first_slice := content[first:int(second)]
			fmt.Println(string(first_slice))
			counterUUID, err := nextCounterID(f.FileUUID, newCounter)
			if err != nil {
				return err
			}
			chunkBytes, ok, err := getStruct(counterUUID, f.EncryptFile, f.HMACFile)
			if !ok {
				return errors.New("wrong")
			}
			if err != nil {
				return err
			}
			c, err := toChunk(chunkBytes)
			c.Content = first_slice
			newChunk, err := json.Marshal(c)
			if err != nil {
				return err
			}
			err = userdata.PushSharedStruct(counterUUID, newChunk, f.EncryptFile, f.HMACFile)
			if err != nil {
				return err
			}
			first += contentPerCounter
			newCounter += 1
		}
		old_count := f.Counter
		f.Counter = newCounter - 1
		newFile, err := json.Marshal(f)
		if err != nil {
			return err
		}
		err = userdata.PushSharedStruct(f.FileUUID, newFile, f.EncryptFile, f.HMACFile)
		if err != nil {
			return err
		}
		for newCounter <= old_count {
			counterUUID, err := nextCounterID(f.FileUUID, newCounter)
			if err != nil {
				return err
			}
			userlib.DatastoreDelete(counterUUID)
			newCounter += 1
		}

	}
	return nil
}
func nextCounterID(id userlib.UUID, counter int) (nextID userlib.UUID, err error) {
	counterBytes := append(id[:], byte(counter))
	finalHash := userlib.Hash(counterBytes)[:16]
	nextID, err = uuid.FromBytes(finalHash)
	if err != nil {
		return uuid.Nil, err
	}

	return nextID, nil

}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	f, ok, err := userdata.GetFile(filename)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("No such file 2")
	}
	f.Counter += 1

	CreateFileChunk(f.FileUUID, f.EncryptFile, f.HMACFile, content, f.Counter)
	if err != nil {
		return err
	}
	fileBytes, err := json.Marshal(f)
	if err != nil {
		return err
	}
	f_bytes, err := EncryptAndMac(fileBytes, f.EncryptFile, f.HMACFile)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(f.FileUUID, f_bytes)
	return nil

}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	f, ok, err := userdata.GetFile(filename)
	if err != nil {
		return nil, err
	}

	//////fmt.Println(ok == false)
	if !ok {
		return nil, errors.New("No such file 3")
	}

	for i := 1; i <= f.Counter; i++ {
		chunkID, err := nextCounterID(f.FileUUID, i)
		if err != nil {
			return nil, err
		}
		chunkBytes, _, err := getStruct(chunkID, f.EncryptFile, f.HMACFile)
		if err != nil {
			return nil, err
		}
		c, err := toChunk(chunkBytes)
		if err != nil {
			return nil, err
		}

		content = append(content, c.Content...)
	}
	return content, nil

}
func (userdata *User) LoadOwnerStruct(filename string) (f *OwnerFile, err error) {
	hasher := userlib.Hash([]byte(userdata.Username))
	hasher = append(hasher, userlib.Hash([]byte(filename))...)
	finalHash := userlib.Hash(hasher)[:16]
	ownerUUID, err := uuid.FromBytes(finalHash)
	if err != nil {
		return nil, err
	}
	toKey := [2]string{"encrypt_ownership", "mac_ownership"}
	userkey := UserkeyGen(userdata.Username, userdata.Password)
	keymap := HashKDFGen(userkey, toKey[:])
	userBytes, ok, err := getStruct(ownerUUID, keymap["encrypt_ownership"], keymap["mac_ownership"])
	if !ok {
		return nil, errors.New("Random")
	}
	if err != nil {
		return nil, err
	}
	f, err = toOwner(userBytes)
	if err != nil {
		return nil, err
	}
	return f, nil
}
func (userdata *User) PushSharedStruct(id userlib.UUID, class []byte, key []byte, mac []byte) (err error) {
	shared_bytes, err := EncryptAndMac(class, key, mac)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(id, shared_bytes)
	return nil
}
func (userdata *User) PushOwnerStruct(class []byte, filename string) (err error) {
	hasher := userlib.Hash([]byte(userdata.Username))
	hasher = append(hasher, userlib.Hash([]byte(filename))...)
	finalHash := userlib.Hash(hasher)[:16]
	ownerUUID, err := uuid.FromBytes(finalHash)
	if err != nil {
		return err
	}
	toKey := [2]string{"encrypt_ownership", "mac_ownership"}
	userkey := UserkeyGen(userdata.Username, userdata.Password)
	keymap := HashKDFGen(userkey, toKey[:])
	userBytes, err := EncryptAndMac(class, keymap["encrypt_ownership"], keymap["mac_ownership"])
	if err != nil {
		return err
	}
	userlib.DatastoreSet(ownerUUID, userBytes)
	return nil
}

/*
	type Shared struct {
		Ownername   []byte
		FileUUID    userlib.UUID //stored at random UUID
		EncryptFile []byte
		HMACFile    []byte

		//holds hash of ownername (only person who can recreate file keys)
		//holds random UUID of file and keys
		//if file gets revoked, through the shared struct of people who still have access, recall storefile on FileStruct and update keys
	}
*/
func CreateSharedStruct(o *OwnerFile) (s *Shared, err error) {
	var sha Shared
	sha.Ownername = o.Ownername
	sha.FileUUID = o.FileUUID
	sha.EncryptFile = o.EncryptFile
	sha.HMACFile = o.HMACFile
	sha.ValidStruct = true
	return &sha, nil

}

type Invite struct {
	ShareID   userlib.UUID
	Sharekey  []byte
	Sharehmac []byte
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	o, err := userdata.LoadOwnerStruct(filename)
	if err != nil {
		return uuid.Nil, err
	}
	var i Invite
	userChecker := userlib.Hash([]byte(userdata.Username))[:16]
	if bytes.Equal(userChecker, o.Ownername) {
		s, err := CreateSharedStruct(o)
		if err != nil {
			return uuid.Nil, err
		}
		SharedUUID := uuid.New()
		SharedKey := userlib.RandomBytes(16)
		SharedHMAC := userlib.RandomBytes(16)
		sharedMapKey := userlib.Hash([]byte(recipientUsername))
		sharedMapKeyString := hex.EncodeToString(sharedMapKey)[:16]
		o.SharedMap[sharedMapKeyString] = SharedUUID
		o.EncryptMap[SharedUUID] = SharedKey
		o.HMACMap[SharedUUID] = SharedHMAC

		s_json, err := json.Marshal(s)
		if err != nil {
			return uuid.Nil, err
		}
		s_bytes, err := EncryptAndMac(s_json, SharedKey, SharedHMAC)
		if err != nil {
			return uuid.Nil, err
		}

		userlib.DatastoreSet(SharedUUID, s_bytes)
		o_bytes, err := json.Marshal(o)
		if err != nil {
			return uuid.Nil, err
		}
		err = userdata.PushOwnerStruct(o_bytes, filename)
		if err != nil {
			return uuid.Nil, err
		}
		i.ShareID = SharedUUID
		i.Sharehmac = SharedHMAC
		i.Sharekey = SharedKey
	} else {
		var sha *Shared
		item, ok, err := getStruct(o.ShareUUID, o.ShareKey, o.ShareMac)
		if !ok {
			return uuid.Nil, errors.New("Random")
		}
		if err != nil {
			return uuid.Nil, err
		}
		sha, err = toShare(item)
		if err != nil {
			return uuid.Nil, err
		}

		if !sha.ValidStruct {
			return uuid.Nil, errors.New("valid")
		} else {
			i.ShareID = o.ShareUUID
			i.Sharehmac = o.ShareMac
			i.Sharekey = o.ShareKey
		}

	}
	i_uuid := uuid.New()
	recipientRSA, ok := userlib.KeystoreGet(recipientUsername + "_rsa")

	if !ok {
		return uuid.Nil, errors.New("no key")
	}

	// //fmt.Println(userdata.Username + " Sigpriv ")
	// //fmt.Println(userdata.PrivateSig)
	// //fmt.Println()

	mysig := userdata.PrivateSig
	i_json, err := json.Marshal(i)

	if err != nil {
		return uuid.Nil, err
	}
	i_bytes, err := RSAAndSig(i_json, recipientRSA, mysig)
	if err != nil {
		return uuid.Nil, err
	}
	userlib.DatastoreSet(i_uuid, i_bytes)
	return i_uuid, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	_, ok, _ := userdata.GetFile(filename)
	if ok {
		return errors.New("File already exists in user namespace")
	}

	err := userdata.CreateOwner(senderUsername, filename, false, nil, invitationPtr)
	if err != nil {
		return err
	}
	return nil
}

func (userdata *User) deleteFile(filename string) (err error) {
	f, _, err := userdata.GetFile(filename)
	for i := 1; i <= f.Counter; i++ {
		chunkID, err := nextCounterID(f.FileUUID, i)
		if err != nil {
			return err
		}
		userlib.DatastoreDelete(chunkID)
	}
	userlib.DatastoreDelete(f.FileUUID)
	return nil

}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	o, err := userdata.LoadOwnerStruct(filename)
	//fmt.Println(o.SharedMap)
	if err != nil {
		return err
	}
	content, err := userdata.LoadFile(filename)
	//fmt.Println(string(content))
	if err != nil {
		return err
	}
	newID, newKey, newHMAC, err := CreateFile(content)
	if err != nil {
		return err
	}
	err = userdata.deleteFile(filename)
	o.FileUUID = newID
	//fmt.Println("new ID")
	//fmt.Println(newID)
	o.EncryptFile = newKey
	o.HMACFile = newHMAC

	sharedMapKey := userlib.Hash([]byte(recipientUsername))
	sharedMapKeyString := hex.EncodeToString(sharedMapKey)[:16]
	_, ok := o.SharedMap[sharedMapKeyString]
	if !ok {
		return errors.New("User already does not have access")
	}
	//fmt.Println("bad string," + sharedMapKeyString)

	EncryptMap := make(map[uuid.UUID][]byte)
	SharedMap := make(map[string]uuid.UUID)
	HMACMap := make(map[uuid.UUID][]byte)
	//fmt.Println(len(o.SharedMap))
	for k, v := range o.SharedMap {
		//fmt.Println("current:" + sharedMapKeyString)
		if k != sharedMapKeyString {
			s_bytes, ok, err := getStruct(v, o.EncryptMap[v], o.HMACMap[v])
			if !ok {
				return errors.New("random")
			}
			if err != nil {
				return err
			}
			s, err := toShare(s_bytes)
			if err != nil {
				return err
			}

			s.FileUUID = o.FileUUID
			s.EncryptFile = o.EncryptFile
			s.HMACFile = o.HMACFile
			SharedMap[k] = v
			EncryptMap[v] = o.EncryptMap[v]
			HMACMap[v] = o.HMACMap[v]
			toStore, err := json.Marshal(s)
			userdata.PushSharedStruct(v, toStore, o.EncryptMap[v], o.HMACMap[v])
		} else {
			s_bytes, ok, err := getStruct(v, o.EncryptMap[v], o.HMACMap[v])
			if !ok {
				return errors.New("random")
			}
			if err != nil {
				return err
			}
			s, err := toShare(s_bytes)
			if err != nil {
				return err
			}
			s.ValidStruct = false
			toStore, err := json.Marshal(s)
			userdata.PushSharedStruct(v, toStore, o.EncryptMap[v], o.HMACMap[v])
			//fmt.Println("down here fella", k)
		}
	}
	o.SharedMap = SharedMap
	o.EncryptMap = EncryptMap
	o.HMACMap = HMACMap
	o_bytes, err := json.Marshal(o)
	if err != nil {
		return err
	}
	err = userdata.PushOwnerStruct(o_bytes, filename)
	if err != nil {
		return err
	}
	return nil

}
