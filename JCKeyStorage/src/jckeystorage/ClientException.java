/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package jckeystorage;

/**
 * A class for KeyStorageClient's errors.
 * @author Ondrej Mosnacek &lt;omosnacek@gmail.com&gt;
 */
public class ClientException extends Exception {
    
    public ClientException(String message) {
        super(message);
    }
    
    public ClientException(String message, Throwable cause) {
        super(message, cause);
    }
}
