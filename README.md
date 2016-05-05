# cryptsetup-javacard
A JavaCard key manager for Cryptsetup.

This is the repository of a school project for the [PV204](https://is.muni.cz/predmet/fi/jaro2016/PV204?lang=en) course on the [Faculty of Informatics of the Masaryk University](https://www.fi.muni.cz) in the term spring 2016.

Team B &ndash; Manoja Kumar Das, Ondrej Mosnáček, Mmabatho Idah Masemene

**WARNING:** This is a proof-of-concept project created by computer security students. Under no circumstances should it be considered secure for normal usage, unless it undergoes a proper review by security professionals :)

## Dependencies

Host machine:
 * Linux
 * [Cryptsetup](https://gitlab.com/cryptsetup/cryptsetup/)
 * JDK 1.8
 * [Apache Ant](https://ant.apache.org/)
 * [JUnit 4](http://junit.org/junit4/)
 * JCDK 2.2.2 (binaries included)
 * [JCardSim 3.0.4](https://jcardsim.org) (binary included)
 * [Bouncy Castle 1.54](https://bouncycastle.org) (binary included)
 * [JCommander 1.49](http://jcommander.org/) (binary included)
 * [GlobalPlaformPro](https://github.com/martinpaljak/GlobalPlatformPro) (binary included)
 * [NetBeans IDE 8](https://netbeans.org/) (for development)

Smart card:
 * JavaCard 2.2.2 (for required algorithms see section *Algorithms*)

## Usage

To use the application, use the scripts located in the `scripts` subdirectory. First, you will need to build the Java application for interacting with the JavaCard (JCKeyStorage):
```bash
$ cd scripts
$ ./build_application.sh
Trying to override old definition of task http://www.netbeans.org/ns/j2se-project/3:test-impl

BUILD SUCCESSFUL
Total time: 1 second
```

The other scripts need to know where JDK 1.8 is installed on your system. If there is an executable called `java` installed on your system (and you have JDK 1.8 set as default), they will determine the path automatically. Otherwise, you need to set the `JAVA_HOME` environment variable to the JDK's home directory:
```bash
$ export JAVA_HOME=/path/to/jdk/1.8
```

For start, you will need to install the KeyStorage JavaCard applet on your card. To do this, run `./install_applet.sh [ARGS...]` where `ARGS` is a list of extra command-line arguments to pass to the GlobalPlatformPro tool (for example `-r <reader_name>` to select the card reader, or `--emv` to work with a card that supports EMV). The script will ask you to specify a master password, which will be required to access the keys stored on the card. Note that the installation may sometimes fail with a `SCARD_E_NOT_TRANSACTED` error -- in such case just retry the installation again.
```bash
$ ./install_applet.sh -r 'ACS ACR1281 1S Dual Reader 00 00' --emv
Compiling the applet...
Enter the master password: 
Confirm the master password: 
Installing the applet using GlobalPlatformPro...
Removing existing package
CAP loaded
Applet has been installed successfully! (Unless you see an error message from GPPro - it doesn't set the exit code properly...)
```

If you want to uninstall the applet, you can use `./delete_applet.sh` in a similar fashion.

To list the card readers connected to your system, you can use the `./list_readers.sh` script:
```bash
$ ./list_readers.sh
[*] ACS ACR1281 1S Dual Reader 00 00
[ ] ACS ACR1281 1S Dual Reader 00 01
[*] ACS ACR1281 1S Dual Reader 00 02
```

After installing the applet, you should retrieve the card's public key and store it somewhere safe (so that noone can modify it without you knowing):
```bash
$ ./get_public_key.sh public.key 'ACS ACR1281 1S Dual Reader 00 00'
Public key has been loaded successfully!
```

If you want to change the card's master password, use the `./change_password.sh` script:
```bash
$ ./change_password.sh public.key 'ACS ACR1281 1S Dual Reader 00 00'
Enter master password: 
Enter new master password: 
Verify new master password: 
Master password has been changed successfully!
```

To create (format) a new LUKS encrypted partition and store it's encryption key on the card, run the `./luks_format.sh` script. The first two arguments are the same as for the previous two commands, the third one is the block device/file to be formatted and the fourth one is the size of the key (in bytes; possible values depend on Cryptsetup configuration). You will be asked to enter the master password twice (this is an implementation limitation, don't ask why ;). You will also be asked to provide a recovery passphrase -- this can be used to access the encrypted data in case you lose the card or it gets broken (using Cryptsetup directly). It should be a very strong passphrase -- best is a long random string that you write down on a piece of paper and put in a safe (after all, you should only need it in an emergency).
```bash
$ ./luks_format.sh public.key 'ACS ACR1281 1S Dual Reader 00 00' /dev/loop0 32
Generating the key and formatting the partition...
Enter master password: 
Saving the key on the card...
Enter master password: 
Please enter an emergency recovery passphrase in case of card loss...
Enter new passphrase for key slot: 
Verify passphrase: 
Successfully formatted device 'device'!
```

To "unlock/open" a partition created by `./luks_format.sh`, use the `./luks_open.sh` script (you will probably need root permissions). You have to specify the name of the mapped device to be created (it will be accessible as `/dev/mappper/<name>`). This device will allow you to access the encrypted data (see [Cryptsetup's documentation](https://gitlab.com/cryptsetup/cryptsetup/wikis/FrequentlyAskedQuestions#2-setup) for more information).
```bash
# ./luks_open.sh public.key 'ACS ACR1281 1S Dual Reader 00 00' /dev/loop0 test
Unlocking partition 30059b10-ee62-4d76-9673-0efeff357773...
Enter master password: 
Successfully opened device '/dev/loop0' as 'test'! 
```

To close the opened partition, just use the Cryptsetup's `close` command:
```bash
# cryptsetup close test
```

To delete a partition's key from the card, you can run `./luks_del_key.sh`. The partition will be left intact (it can still be accessed using the recovery passphrase).
```bash
$ ./luks_del_key.sh public.key 'ACS ACR1281 1S Dual Reader 00 00' /dev/loop0
Deleting key of partition 30059b10-ee62-4d76-9673-0efeff357773...
Enter master password: 
Successfully deleted key for device 'device'!
```

If you want to also erase the recovery passphrase data from the partition header, use `./luks_erase.sh` instead. WARNING: The encrypted data will no longer be recoverable after this operation!
```bash
$ ./luks_erase.sh public.key 'ACS ACR1281 1S Dual Reader 00 00' /dev/loop0
Deleting key of partition 30059b10-ee62-4d76-9673-0efeff357773...
Enter master password:
Erasing the partition header...
Successfully erased keys for device '/dev/loop0'!
```

## Required JavaCard algorithms
The applet requires the card to support the following algorithms:

**javacard.security.KeyBuilder**
 * `TYPE_EC_FP_*` with `LENGTH_EC_FP_192`
 * `TYPE_RSA_*` with `LENGTH_RSA_1024`
 * `TYPE_AES_TRANSIENT_DESELECT` with `LENGTH_AES_256`

**javacard.security.KeyPair** (key pair generation)
 * `ALG_RSA_CRT` with `LENGTH_RSA_1024`
 * `ALG_EC_FP` with `LENGTH_EC_FP_192` (with preset curve parameters)

**javacard.security.Signature**
 * `ALG_RSA_SHA_PKCS1`

**javacard.security.MessageDigest**
 * `ALG_SHA_256`

**javacard.security.RandomData**
 * `ALG_SECURE_RANDOM`

**javacardx.crypto.Cipher**
 * `ALG_AES_BLOCK_128_CBC_NOPAD`

The card must also support ISO7816-4 defined extended length APDU messages.
