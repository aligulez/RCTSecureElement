/**
 * Sample React Native App
 * https://github.com/facebook/react-native
 */
'use strict';


var React = require('react-native');
var {
  AppRegistry,
  StyleSheet,
  Text,
  View,
  TouchableHighlight,
  NativeModules,
} = React;

var iosParameters = {
  clearText: "abcdefghijklmnoprs abcdefghijklmnoprs abcdefghijklmnoprs abcdefghijklmnoprs",
  clearTextForSigning: "bearandfox",
  signedHash: "default",
  verified: "default",
  publicKey: "default",
  encryptedText: "default",
  decryptedText: "default"
};

var RCTSecureElement = React.createClass({

  generateKeyPairs: function(){

    NativeModules.SecurityController.generatePair('EC', (text) => {
      
      iosParameters.publicKey = text ;       
      //console.log(iosParameters.publicKey) ;

    });

  },
  encrypt: function(){
    
    NativeModules.SecurityController.encryptInputString(iosParameters.clearText,iosParameters.publicKey, (text) => {
      
      iosParameters.encryptedText = text ;      
      //console.log(iosParameters.encryptedText) ;

    });
    
  },
  decrypt: function(){

     NativeModules.SecurityController.decryptCipher(iosParameters.encryptedText, (text) => {

      iosParameters.decryptedText = text ;      
      console.log(iosParameters.decryptedText) ;

    });

  },
  sign: function(){

     NativeModules.SecurityController.sign(iosParameters.clearTextForSigning, (text) => {

      iosParameters.signedHash = text ;      
      //console.log(iosParameters.signedHash) ;

    });

  },
  verify: function(){

     NativeModules.SecurityController.verify(iosParameters.clearTextForSigning,iosParameters.publicKey,iosParameters.signedHash, (text) => {

      iosParameters.verified = text ;      
      console.log(iosParameters.verified) ;
      
    });

  },
  render: function() {
    return (
      <View style={styles.container}>
        <TouchableHighlight onPress={this.generateKeyPairs} underlayColor="white">
          <Text style={styles.welcome}>
           Generate Key Pairs
          </Text>
        </TouchableHighlight>
        <TouchableHighlight onPress={this.sign} underlayColor="white">
          <Text style={styles.welcome}>
           Sign
          </Text>
        </TouchableHighlight>
        <TouchableHighlight onPress={this.verify} underlayColor="white">
          <Text style={styles.welcome}>
           Verify
          </Text>
        </TouchableHighlight>
        <TouchableHighlight onPress={this.encrypt} underlayColor="white">
          <Text style={styles.welcome}>
           Encrypt
          </Text>
        </TouchableHighlight>   
        <TouchableHighlight onPress={this.decrypt} underlayColor="white">
          <Text style={styles.welcome}>
            Decrypt
          </Text>
        </TouchableHighlight>        
      </View>
    );
  }
});


var styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  },
  welcome: {
    fontSize: 20,
    textAlign: 'center',
    margin: 10,
  },
  instructions: {
    textAlign: 'center',
    color: '#333333',
    marginBottom: 5,
  },
});

AppRegistry.registerComponent('RCTSecureElement', () => RCTSecureElement);
