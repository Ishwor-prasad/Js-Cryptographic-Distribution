const KeyChain = require("./password-manager");
const { subtle } = require("crypto").webcrypto;
const crypto = require("crypto");
const fs = require("fs").promises;
const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const storageFile = "masterKey.txt";
const KVSfile = "kvs.txt";

function ask(question) {
  // Return a new Promise that encapsulates the asynchronous operation
  return new Promise((resolve, reject) => {
    // Use readline to prompt the user with the provided question
    rl.question(question, (answer) => {
      // Once the user provides an answer, resolve the Promise with the answer
      resolve(answer);
    });
  });
}


async function loadKVSfromFile() {
  try {
    const content = await fs.readFile(KVSfile, "utf-8");
    const lines = content.trim().split("\n").slice(1); // Remove header line and split into individual lines
    const kvs = {};
    for (const line of lines) {
      const [key, iv, ciphertextBase64, byteLength] = line.split(","); // Split line into columns
      const ciphertext = Buffer.from(ciphertextBase64, "base64");
      kvs[key] = { iv, ciphertext, byteLength: parseInt(byteLength, 10) };
    }

    kvsdata = conversion(kvs);

    const finalConvertedKVS = convertedKVS(kvsdata);

    return finalConvertedKVS;
  } catch (error) {
    console.error("Failed to load KVS:", error.message);
    return {};
  }
}

// function conversion(kvs) {
//   const kvsdata = {};
//   for (const key in kvs) {
//     const cleanKey = key.replace(/"/g, ""); // Remove extra quotes
//     const iv = kvs[key].iv.replace(/"/g, ""); // Remove extra quotes
//     const ciphertext = kvs[key].ciphertext.buffer; // Convert Buffer to ArrayBuffer
//     console.log("ciphertext: ", ciphertext);
//     kvsdata[cleanKey] = {
//       iv,
//       ciphertext,
//       byteLength: kvs[key].byteLength,
//     };
//   }
//   return kvsdata;
// }

function conversion(input) {
  const loadedKVS = {};
  for (const key in input) {
    const iv = input[key].iv;
    const ciphertext = `<Buffer ${input[key].ciphertext.toString("hex")}>`;
    loadedKVS[key] = { iv, ciphertext };
  }
  return loadedKVS;
}

function convertedKVS(loadedKVS) {
  const convertedKVS = {};
  for (const key in loadedKVS) {
    const cleanKey = key.replace(/"/g, ""); // Remove extra quotes
    const iv = loadedKVS[key].iv.replace(/"/g, ""); // Remove extra quotes
    const ciphertextString = loadedKVS[key].ciphertext
      .replace(/^<Buffer /, "")
      .replace(/>$/, "")
      .replace(/ /g, "");
    const ciphertextBytes = ciphertextString
      .match(/.{1,2}/g)
      .map((byte) => parseInt(byte, 16)); // Convert hex string to array of bytes
    const ciphertext = new Uint8Array(ciphertextBytes).buffer; // Convert array of bytes to ArrayBuffer

    convertedKVS[cleanKey] = {
      iv,
      ciphertext,
    };
  }

  return convertedKVS;
}

async function storeKVStoFile(kvs) {
  try {
    let content = "key,iv,ciphertext,byteLength\n";
    for (const key in kvs) {
      const iv = kvs[key].iv;
      const ciphertext = Buffer.from(kvs[key].ciphertext).toString("base64");
      const byteLength = kvs[key].ciphertext.byteLength;
      content += `"${key}","${iv}","${ciphertext}",${byteLength}\n`;
    }
    await fs.writeFile(KVSfile, content);
    console.log("KVS stored successfully.");
  } catch (error) {
    console.error("Failed to store KVS:", error);
  }
}

async function loadMasterKey() {
  try {
    // Read the contents of the storage file asynchronously
    const keyData = await fs.readFile(storageFile);

    // Import the key data as a cryptographic key using the Web Crypto API
    //The Web Crypto API is designed to be secure and efficient, providing
    //a standardized interface for cryptographic operations across different web browsers.
    // It enables web developers to build secure web applications that handle sensitive data
    //without relying on external libraries or plugins.
    const importedKey = await subtle.importKey(
      "raw", // Specify the format of the key data
      keyData, // Provide the key data to be imported
      { name: "AES-GCM" }, // Specify the cryptographic algorithm (AES-GCM)
      false, // Indicate whether the key is extractable (false to prevent extraction)
      ["encrypt", "decrypt"] // Specify the key's purpose (encrypt and decrypt)
    );

    // Return the imported key
    return importedKey;
  } catch (error) {
    // Handle errors that occur during key loading
    console.error("Error loading derived key:", error.message);
    // Return null if the file doesn't exist or cannot be read
    return null;
  }
}


// Function to load the master key from file
// async function loadMasterKey() {
//   try {
//     const keyData = await fs.readFile(storageFile, "utf-8");
//     return await subtle.importKey(
//       "raw",
//       Buffer.from(keyData, "hex"),
//       { name: "PBKDF2" },
//       false,
//       ["deriveKey"]
//     );
//   } catch (error) {
//     return null; // Return null if file doesn't exist or cannot be read
//   }
// }

// Function to store the master key to file
async function storeMasterKey(derivedKey) {
  const exportedKey = Buffer.from(await subtle.exportKey("raw", derivedKey));
  await fs.writeFile(storageFile, exportedKey);
}

async function deriveMasterKey(masterPassword) {
  /*    Generate a Salt: Generates a random salt using crypto.randomBytes.
  The salt is used to add complexity to the key derivation process and mitigate against precomputed attacks.

    Import Key Material: Imports the master password as key material using the subtle.importKey method of the Web Crypto API.
     This step prepares the master password for use in the key derivation process.

    Derive Key: Derives a key from the master password using the crypto.subtle.deriveKey method of the Web Crypto API.
    This step applies the PBKDF2 algorithm to the master password to produce a derived key suitable for encryption and decryption.

    Return Derived Key: Returns the derived key, which can be used for encryption and decryption operations in the application.*/
  // Generate a random salt
  const salt = crypto.randomBytes(16);

  // Import the master password as key material using the Web Crypto API
  const keyMaterial = await subtle.importKey(
    "raw", // Specify the format of the key data
    encode(masterPassword), // Encode the master password to be used as key data
    { name: "PBKDF2" }, // Specify the cryptographic algorithm (PBKDF2)
    false, // Indicate whether the key is extractable (false to prevent extraction)
    ["deriveKey"] // Specify the key's purpose (key derivation)
  );

  // Derive a key from the master password using PBKDF2
  return crypto.subtle.deriveKey(
    { // Specify the PBKDF2 parameters
      name: "PBKDF2", // Specify the name of the algorithm (PBKDF2)
      salt, // Provide the salt used for key derivation
      iterations: 100000, // Specify the number of iterations
      hash: "SHA-256" // Specify the hash algorithm (SHA-256)
    },
    keyMaterial, // Provide the key material (master password)
    { // Specify the derived key parameters
      name: "AES-GCM", // Specify the cryptographic algorithm for the derived key (AES-GCM)
      length: 256 // Specify the length of the derived key (256 bits)
    },
    true, // Indicate whether the derived key is extractable
    ["encrypt", "decrypt"] // Specify the key's purpose (encrypt and decrypt)
  );
}

async function main() {
  // Load the master key asynchronously
  const loadKey = await loadMasterKey();

  let masterPassword;
  let derivedKey = loadKey;

  // Check if a master key was loaded successfully
  if (loadKey === null) {
    // If no master key is loaded, prompt the user to enter their master password
    masterPassword = await ask("Enter your master password: ");

    // Derive the master key from the provided master password
    derivedKey = await deriveMasterKey(masterPassword);

    // Store the derived master key
    await storeMasterKey(derivedKey);
  }
}


  let loadKVS = {};
  loadKVS = await loadKVSfromFile();

  const keychain = new KeyChain(derivedKey, loadKVS);

  while (true) {
    const action = await ask(
      "\n*********************************\nEnter action: \n**1 to get password **\n**2 to set password **\n**3 to remove password **\n**Write exit to exit**\n*********************************\nAction:  "
    );
    if (action === "exit") {
      console.log("Exiting...");
      await storeKVStoFile(keychain.kvs);
      process.exit(0);
    }

    switch (action) {
      case "1":
        const nameToGet = await ask(
          "\n*********************************\nEnter name to retrieve password: "
        );
        const password = await keychain.get(nameToGet);
        if (password !== null) {
          console.log(
            `Password for ${nameToGet}: ${password}\n*********************************`
          );
        } else {
          console.log(
            `No password found for ${nameToGet}.\n*********************************`
          );
        }
        break;
      case "2":
        const domainName = await ask(
          "\n*********************************\nEnter name to set password for: "
        );
        const passwordDomain = await ask("Enter password: ");
        await keychain.set(domainName, passwordDomain);
        console.log(
          `Password for ${domainName} set successfully.\n*********************************`
        );
        break;
      case "3":
        const nameToRemove = await ask(
          "\n*********************************\nEnter name to remove password for: "
        );
        const removed = await keychain.remove(nameToRemove);
        if (removed) {
          console.log(
            `Password for ${nameToRemove} removed successfully.\n*********************************`
          );
        } else {
          console.log(
            `No password found for ${nameToRemove}.\n*********************************`
          );
        }
        break;
      default:
        console.log(
          "\n*********************************\nInvalid action. Please try again.\n*********************************"
        );
        break;
    }
  }
}

main().catch(console.error);
