from burp import IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener, IContextMenuInvocation, IHttpRequestResponse
from javax.swing import (JScrollPane, JPanel,JList, JTabbedPane, JTextField, JLabel, JTextArea, JButton, JEditorPane, JMenuItem, JComboBox, JCheckBox, JOptionPane, JProgressBar, GroupLayout,LayoutStyle)        
from java.lang import Short
from java.awt import Color,Dimension,BorderLayout
from HTMLParser import HTMLParser
from binascii import hexlify, unhexlify
import re
import threading
import Queue
import random
import base64
import urllib
import cgi
import binascii
import time
import json
from java.util import Base64
from collections import Counter, namedtuple
import hashlib



class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        # Set up the context menu        
        callbacks.setExtensionName("Crypto Revenger")
        callbacks.registerExtensionStateListener(self)
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.registerContextMenuFactory(self)

        # Create  GUI
        self.createGUIForCRIME()
        self.createGUIForBAAT()
        self.createGUIForEncode()
        self._cryptoRevengerTab= JTabbedPane()
        self._cryptoRevengerTab.addTab("CRIME ATTACK", self._CrimeAttackJPanel)
        self._cryptoRevengerTab.addTab("BYTE AT A TIME ATTACK", self._BAATAttackJPanel)
        self._cryptoRevengerTab.addTab("Encode and Decode", self.tab)
        callbacks.customizeUiComponent(self._cryptoRevengerTab)
        callbacks.addSuiteTab(self)

    def createMenuItems(self, invocation):
        menu = []
        ctx = invocation.getInvocationContext()
        if ctx == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST or ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST:
            menu.append(JMenuItem("CRIME ATTACK", None, actionPerformed=lambda x, inv=invocation: self.CRIME(inv)))
            menu.append(JMenuItem("BYTE AT A TIME ATTACK", None, actionPerformed=lambda x, inv=invocation: self.BAAT(inv)))              
        return menu if menu else None

    def getTabCaption(self):        
        return "Crypto Revenger"
    def getUiComponent(self):
        return self._cryptoRevengerTab

    def CRIME(self, invocation):
        self.crimeRequestToHandle=""
        self.crimeSelectedPayload=""
        invMessages  = invocation.getSelectedMessages()
        if len(invMessages) == 0:
            return
        self.crimerequestMessage = invMessages[0]
        self.stringCrimerequestMessage = self._helpers.bytesToString(self.crimerequestMessage.getRequest())         
        self._CrimeRequestJEditorPane.setText(self.stringCrimerequestMessage)
              
        self._cryptoRevengerTab.setSelectedComponent(self._CrimeAttackJPanel)
        parentTab = self._cryptoRevengerTab.getParent()
        parentTab.setSelectedComponent(self._cryptoRevengerTab)

    def BAAT(self,invocation):

        self.BAATRequestToHandle=""
        self.BAATSelectedPayload=""
        invMessages  = invocation.getSelectedMessages()
        if len(invMessages) == 0:
            return
        self.BAATrequestMessage = invMessages[0]
        self.stringBAATrequestMessage = self._helpers.bytesToString(self.BAATrequestMessage.getRequest())         
        self._BAATRequestJEditorPane.setText(self.stringBAATrequestMessage)
              
        self._cryptoRevengerTab.setSelectedComponent(self._BAATAttackJPanel)
        parentTab = self._cryptoRevengerTab.getParent()
        parentTab.setSelectedComponent(self._cryptoRevengerTab)


    def requestHandleForCrimeAttack(self,payload):
        if self.crimeFormatPayload=="Base64":
            newHttpRequest = self.crimeRequestToHandle.replace("###PAYLOAD###", base64.b64encode(payload).decode())
        else:
            newHttpRequest = self.crimeRequestToHandle.replace("###PAYLOAD###", binascii.hexlify(payload.decode()).decode())
        reqInfo = self._helpers.analyzeRequest(newHttpRequest)
        headers = reqInfo.getHeaders()            
        param = newHttpRequest[reqInfo.getBodyOffset():]      
        newHttpRequest = self._helpers.buildHttpMessage(headers, param)                  
        httpService = self.crimerequestMessage.getHttpService()                       
        res = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(httpService.getHost(),httpService.getPort(), httpService.getProtocol()), newHttpRequest)                        
        return res.getResponse()

    ########################################################################
    # custom this function  
    def analyzeResponseForCrime(self,response):
        resInfo = self._helpers.analyzeResponse(response)    
        body = response[resInfo.getBodyOffset():]            
        jsonResponse=json.loads(self._helpers.bytesToString(body))
        return len(jsonResponse["ciphertext"])
    ########################################################################

    def attackForCrime(self):
        charList='abcdefghijklmnopqrstuvwxyz}{ABCDEFGHIJKLMNOPQRTSUVWXYZ0123456789_'
        result=self.crimePrefixResult
        baseValueForProcessBar=100//int(self.crimeLengthResult)
        currentvalueForProcessBar=0
        for _ in range(int(self.crimeLengthResult)):
            payloadInvalid=(result+self.crimeInvalidChar)*3
            invalidDataResponse=self.analyzeResponseForCrime(self.requestHandleForCrimeAttack(payloadInvalid))
            for char in charList:
                payload=(result+char)*3
                dataResponse=self.analyzeResponseForCrime(self.requestHandleForCrimeAttack(payload))
                if dataResponse<invalidDataResponse:
                    result+=char
                    self._CrimeResultJText.text=result
                    currentvalueForProcessBar+=baseValueForProcessBar
                    self._CrimeStatusProgressBar.setValue(currentvalueForProcessBar)
                    break
        self._CrimeStatusProgressBar.setValue(100)
        self._CrimeStatusProgressBar.setString("Finish!")
        return 

    def crimeAttack(self,event):
        self.crimeLengthResult=self._CrimeLengthJText.text
        self.crimePrefixResult=self._CrimePrefixJText.text
        self.crimeInvalidChar=self._CrimeInvalidCharJText.text
        self.crimeFormatPayload=self._CrimeTypePayloadJComboBox.getSelectedItem()
        self._CrimeStatusProgressBar.setValue(0)
        
        # Start Thread
        self._CrimeStatusProgressBar.setString("Attacking...")
        self.crimeThread = threading.Thread(target=self.attackForCrime)                        
        self.crimeThread.start()
        return 


    def selectPayloadIndexForCrime(self,event):            
        self.crimeSelectedPayload = self._CrimeRequestJEditorPane.getSelectedText().replace("\n", "")          
        self.crimeRequestToHandle=self.stringCrimerequestMessage.replace(self.crimeSelectedPayload, "###PAYLOAD###")       
        bytesDisplay = self.stringCrimerequestMessage.encode()        
        insertSpecialChar = chr(167)                         
        bytesDisplay = bytesDisplay.replace(self.crimeSelectedPayload.encode(), insertSpecialChar + self.crimeSelectedPayload.encode() + insertSpecialChar)             
        self._CrimeRequestJEditorPane.setText(bytesDisplay)
        return

    def clearPayloadIndexForCrime(self,event):
        if self.crimeSelectedPayload=="":
            return 
        else:
            originalRequest=self.crimeRequestToHandle.replace("###PAYLOAD###",self.crimeSelectedPayload)
            self.crimeRequestToHandle=""
            self.crimeSelectedPayload=""
            self._CrimeRequestJEditorPane.setText(originalRequest)

        return


    def createGUIForCRIME(self):
        self._CrimeAttackJPanel=JPanel()
        self._CrimeRequestJScrollPane = JScrollPane()
        self._CrimeRequestJEditorPane = JEditorPane()
        self._CrimeRequestJLabel = JLabel()
        self._CrimeResultJText = JTextField()
        self._CrimeResultJLabel = JLabel()
        self._CrimeSelectIndexJButton = JButton(actionPerformed=self.selectPayloadIndexForCrime)
        self._CrimePrefixJText = JTextField()
        self._CrimeInvalidCharJLabel = JLabel()
        self._CrimeInvalidCharJText = JTextField()
        self._CrimePrefixJLabel = JLabel()
        self._CrimeLengthJLabel = JLabel()
        self._CrimeLengthJText = JTextField()
        self._CrimeAttackJButton = JButton(actionPerformed=self.crimeAttack)
        self._CrimeTypePayloadJComboBox = JComboBox(["Base64","Hex"])
        self._CrimeClearIndexJButton = JButton(actionPerformed=self.clearPayloadIndexForCrime)
        self._CrimeStatusProgressBar = JProgressBar(0, 100)
        self._CrimeStatusProgressBar.setStringPainted(True)

        self._CrimeRequestJScrollPane.setViewportView(self._CrimeRequestJEditorPane)

        self._CrimeRequestJLabel.setText("Request")

        self._CrimeResultJLabel.setText("Result")

        self._CrimeSelectIndexJButton.setText("Select Index ")

        self._CrimeInvalidCharJLabel.setText("Invalid Char")

        self._CrimePrefixJLabel.setText("Prefix ")

        self._CrimeLengthJLabel.setText("Length")

        self._CrimeAttackJButton.setText("Attack")


        self._CrimeClearIndexJButton.setText("Clear Index ")


        layout = GroupLayout(self._CrimeAttackJPanel)
        self._CrimeAttackJPanel.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(293, 293, 293)
                .addComponent(self._CrimeSelectIndexJButton)
                .addGap(167, 167, 167)
                .addComponent(self._CrimeClearIndexJButton)
                .addGap(154, 154, 154)
                .addComponent(self._CrimeTypePayloadJComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addContainerGap(265, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(137, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self._CrimeResultJLabel)
                    .addComponent(self._CrimeInvalidCharJLabel)
                    .addComponent(self._CrimePrefixJLabel)
                    .addComponent(self._CrimeLengthJLabel))
                .addGap(29, 29, 29)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                    .addComponent(self._CrimeStatusProgressBar, GroupLayout.DEFAULT_SIZE, 903, Short.MAX_VALUE)
                    .addComponent(self._CrimePrefixJText)
                    .addComponent(self._CrimeResultJText, GroupLayout.Alignment.TRAILING)
                    .addComponent(self._CrimeRequestJLabel)
                    .addComponent(self._CrimeRequestJScrollPane, GroupLayout.Alignment.TRAILING)
                    .addComponent(self._CrimeInvalidCharJText)
                    .addComponent(self._CrimeLengthJText))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(self._CrimeAttackJButton, GroupLayout.PREFERRED_SIZE, 102, GroupLayout.PREFERRED_SIZE)
                .addGap(452, 452, 452))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(35, 35, 35)
                .addComponent(self._CrimeRequestJLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(self._CrimeRequestJScrollPane, GroupLayout.PREFERRED_SIZE, 249, GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._CrimeSelectIndexJButton)
                    .addComponent(self._CrimeTypePayloadJComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._CrimeClearIndexJButton))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self._CrimeInvalidCharJText, GroupLayout.PREFERRED_SIZE, 35, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._CrimeInvalidCharJLabel))
                .addGap(30, 30, 30)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self._CrimePrefixJText, GroupLayout.PREFERRED_SIZE, 35, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._CrimePrefixJLabel))
                .addGap(28, 28, 28)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addComponent(self._CrimeLengthJText, GroupLayout.PREFERRED_SIZE, 37, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._CrimeLengthJLabel))
                .addGap(19, 19, 19)
                .addComponent(self._CrimeAttackJButton, GroupLayout.PREFERRED_SIZE, 47, GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(self._CrimeStatusProgressBar, GroupLayout.PREFERRED_SIZE, 31, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._CrimeResultJText, GroupLayout.PREFERRED_SIZE, 62, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._CrimeResultJLabel)))
        )
    
#################################################################################################################################################
    def requestHandleForBAATAttack(self,payload):
        if self.BAATFormatPayload=="Base64":
            newHttpRequest = self.BAATRequestToHandle.replace("###PAYLOAD###", base64.b64encode(payload).decode())
        else:
            newHttpRequest = self.BAATRequestToHandle.replace("###PAYLOAD###", binascii.hexlify(payload.decode()))  
        reqInfo = self._helpers.analyzeRequest(newHttpRequest)
        headers = reqInfo.getHeaders()            
        param = newHttpRequest[reqInfo.getBodyOffset():]      
        newHttpRequest = self._helpers.buildHttpMessage(headers, param)                  
        httpService = self.BAATrequestMessage.getHttpService()                       
        res = self._callbacks.makeHttpRequest(self._helpers.buildHttpService(httpService.getHost(),httpService.getPort(), httpService.getProtocol()), newHttpRequest)                        
        return res.getResponse()

    ########################################################################
    # custom this function 
    def analyzeResponseForBAAT(self,response):
        resInfo = self._helpers.analyzeResponse(response)   
        body = response[resInfo.getBodyOffset():]
        jsonResponse=json.loads(self._helpers.bytesToString(body))
        return binascii.unhexlify(jsonResponse["ciphertext"])
    ########################################################################

    def reconForGetLength(self):
        baseLength=len(self.analyzeResponseForBAAT(self.requestHandleForBAATAttack('a')))
        #print("into base")
        for i in range(1,17):
            tmpLength=len(self.analyzeResponseForBAAT(self.requestHandleForBAATAttack('a'*i)))
            if tmpLength>baseLength:
                if tmpLength==16:
                    return baseLength-16
                else:
                    return baseLength-i
        return baseLength-17

    def attackForBAAT(self): 
        charList='abcdefghijklmnopqrstuvwxyz}{ABCDEFGHIJKLMNOPQRTSUVWXYZ0123456789_'
        lengthResult=self.reconForGetLength()
        baseValueForProcessBar=100//lengthResult
        currentvalueForProcessBar=0
        result=''
        tmpValue=(lengthResult//16+1)*16
        input='a'*tmpValue
        k=0
        while k<lengthResult:

            ref_block=self.analyzeResponseForBAAT(self.requestHandleForBAATAttack(input[:-1]))[:tmpValue]
            for i in charList: 
                r = self.analyzeResponseForBAAT(self.requestHandleForBAATAttack(input[:-1]+result+i))[:tmpValue]
                if r==ref_block:
                    result+=i
                    self._BAATResultJText.text=result
                    currentvalueForProcessBar+=baseValueForProcessBar
                    self._BAATStatusProgressBar.setValue(currentvalueForProcessBar)
                    break
            k+=1
            input=input[:-1]
      
        self._BAATStatusProgressBar.setValue(100)
        self._BAATStatusProgressBar.setString("Finish!")
        return



    def BAATAttack(self,event):
        self.BAATFormatPayload=self._BAATTypePayloadJComboBox.getSelectedItem()
        self._BAATStatusProgressBar.setValue(0)
        # Start 
        self._BAATStatusProgressBar.setString("Attacking...")
        self.BAATExitFlag=False
        self.BAATThread = threading.Thread(target=self.attackForBAAT)                       
        self.BAATThread.start()
        return 
        
    
    def selectPayloadIndexForBAAT(self,event):           
        self.BAATSelectedPayload = self._BAATRequestJEditorPane.getSelectedText().replace("\n", "")
        self.BAATRequestToHandle=self.stringBAATrequestMessage.replace(self.BAATSelectedPayload, "###PAYLOAD###")
        bytesDisplay = self.stringBAATrequestMessage.encode()        
        insertSpecialChar = chr(167)                         
        bytesDisplay = bytesDisplay.replace(self.BAATSelectedPayload.encode(), insertSpecialChar + self.BAATSelectedPayload.encode() + insertSpecialChar)             
        self._BAATRequestJEditorPane.setText(bytesDisplay)
        return

    def clearPayloadIndexForBAAT(self,event):
        if self.BAATSelectedPayload=="":
            return 
        else:
            originalRequest=self.BAATRequestToHandle.replace("###PAYLOAD###",self.BAATSelectedPayload)
            self.BAATRequestToHandle=""
            self.BAATSelectedPayload=""
            self._BAATRequestJEditorPane.setText(originalRequest)
        return


    def createGUIForBAAT(self):
        self._BAATAttackJPanel=JPanel()
        self._BAATRequestJLabel =JLabel()
        self._BAATSelectIndexJButton =JButton(actionPerformed=self.selectPayloadIndexForBAAT)
        self._BAATClearIndexJButton =JButton()
        self._BAATTypePayloadJComboBox =JComboBox(["Hex","Base64"])
        self._BAATResultJText =JTextField()
        self._BAATResultJLabel =JLabel()
        self._BAATAttackJButton =JButton(actionPerformed=self.BAATAttack)
        self._BAATJScrollPane =JScrollPane()
        self._BAATRequestJEditorPane =JEditorPane()
        self._BAATStatusProgressBar =JProgressBar()
        self._BAATStatusProgressBar.setStringPainted(True)

        self._BAATRequestJLabel.setText("Request")

        self._BAATSelectIndexJButton.setText("Select Index")

        self._BAATClearIndexJButton.setText("Clear Index")

        self._BAATResultJLabel.setText("Result")


        self._BAATAttackJButton.setText("Attack")

        self._BAATJScrollPane.setViewportView(self._BAATRequestJEditorPane)

        layout =GroupLayout(self._BAATAttackJPanel)
        self._BAATAttackJPanel.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(self._BAATAttackJButton, GroupLayout.PREFERRED_SIZE, 84, GroupLayout.PREFERRED_SIZE)
                .addGap(148, 148, 148)
                .addGap(369, 369, 369))
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addGroup(layout.createSequentialGroup()
                                    .addGap(292, 292, 292)
                                    .addComponent(self._BAATSelectIndexJButton, GroupLayout.PREFERRED_SIZE, 106, GroupLayout.PREFERRED_SIZE)
                                    .addGap(151, 151, 151)
                                    .addComponent(self._BAATClearIndexJButton)
                                    .addGap(167, 167, 167)
                                    .addComponent(self._BAATTypePayloadJComboBox, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
                                .addGroup(layout.createSequentialGroup()
                                    .addGap(207, 207, 207)
                                    .addComponent(self._BAATRequestJLabel)))
                            .addGap(148, 148, 148))
                        .addGroup(layout.createSequentialGroup()
                            .addContainerGap()
                            .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                .addGroup(GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                    .addComponent(self._BAATResultJLabel)
                                    .addGap(51, 51, 51)
                                    .addComponent(self._BAATResultJText, GroupLayout.PREFERRED_SIZE, 818, GroupLayout.PREFERRED_SIZE))
                                .addComponent(self._BAATJScrollPane, GroupLayout.Alignment.TRAILING, GroupLayout.PREFERRED_SIZE, 818, GroupLayout.PREFERRED_SIZE))))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(276, 276, 276)
                        .addComponent(self._BAATStatusProgressBar, GroupLayout.PREFERRED_SIZE, 675, GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(105, Short.MAX_VALUE))
       )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(30, 30, 30)
                .addComponent(self._BAATRequestJLabel)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(self._BAATJScrollPane, GroupLayout.PREFERRED_SIZE, 359, GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._BAATSelectIndexJButton, GroupLayout.PREFERRED_SIZE, 35, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._BAATClearIndexJButton, GroupLayout.PREFERRED_SIZE, 35, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._BAATTypePayloadJComboBox, GroupLayout.PREFERRED_SIZE, 35, GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._BAATAttackJButton, GroupLayout.PREFERRED_SIZE, 40, GroupLayout.PREFERRED_SIZE))
                .addGap(47, 47, 47)
                .addComponent(self._BAATStatusProgressBar, GroupLayout.PREFERRED_SIZE, 27, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(self._BAATResultJText, GroupLayout.PREFERRED_SIZE, 76, GroupLayout.PREFERRED_SIZE)
                    .addComponent(self._BAATResultJLabel))
                .addGap(85, 85, 85))
       )

    def createGUIForEncode(self):

        self.tab = JPanel(BorderLayout())
        self.handlePanel=JPanel()


        def handleSelectValueList(event):
            value = listElement[jListElement.selectedIndex]
            if value=="Encoding":
                self.handlePanel.setVisible(False)
                self.handlePanel=self.createHandleEncoding()
                self.tab.add(self.handlePanel)
            elif value=="Decoding":
                self.handlePanel.setVisible(False)
                self.handlePanel=self.createHandleDecoding()
                self.tab.add(self.handlePanel)
            elif value=="Hash":
                self.handlePanel.setVisible(False)
                self.handlePanel=self.createHandleHashing()
                self.tab.add(self.handlePanel)
            return

        listElement=["Encoding","Decoding","Hash"]
        jListElement=JList(listElement,valueChanged=handleSelectValueList)
        spane = JScrollPane()
        spane.setPreferredSize(Dimension(200,350))
        spane.getViewport().setView((jListElement))
        self.chooseModePanel = JPanel()
        self.chooseModePanel.add(spane)
        self.tab.add(self.chooseModePanel,BorderLayout.WEST)
        
    def createHandleEncoding(self):
        def handleEncodeButton(event):
            base64JText.text = base64.b64encode(inputJText.text)
            hexJText.text = binascii.hexlify(inputJText.text)
            urlEncodeJText.text = urllib.quote(inputJText.text)
            htmlEncodeJText.text = cgi.escape(inputJText.text)
            return
            
        inputJLabel =JLabel()
        base64JText =JTextField()
        encodeButton =JButton("",actionPerformed=handleEncodeButton)
        hexJText =JTextField()
        urlEncodeJText =JTextField()
        htmlEncodeJText =JTextField()
        inputJText =JTextField()
        base64JLabel =JLabel()
        hexJLabel =JLabel()
        urlEncodeJLabel =JLabel()
        htmlEncodeJLabel =JLabel()
        inputJLabel.setText("Input")
        encodeButton.setText("Encode")
        base64JLabel.setText("Base64")
        hexJLabel.setText("Hex")
        urlEncodeJLabel.setText("Url Encode")
        htmlEncodeJLabel.setText("HTML encode")
        self.handleEncodingPanel=JPanel()
        layout = GroupLayout(self.handleEncodingPanel)
        self.handleEncodingPanel.setLayout(layout)


        layout = GroupLayout(self.handleEncodingPanel)
        self.handleEncodingPanel.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(encodeButton)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, 28, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING, False)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(htmlEncodeJLabel)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(htmlEncodeJText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                            .addComponent(base64JLabel, GroupLayout.Alignment.LEADING)
                            .addComponent(hexJLabel, GroupLayout.Alignment.LEADING)
                            .addComponent(urlEncodeJLabel, GroupLayout.Alignment.LEADING)
                            .addComponent(inputJLabel, GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 47, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(urlEncodeJText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(38, 38, 38)
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                                    .addComponent(base64JText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE)
                                    .addComponent(inputJText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE)
                                    .addComponent(hexJText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE))))))
                .addGap(26, 26, 26))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(277, 277, 277)
                        .addComponent(encodeButton, GroupLayout.PREFERRED_SIZE, 38, GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(16, 16, 16)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(inputJText, GroupLayout.PREFERRED_SIZE, 117, GroupLayout.PREFERRED_SIZE)
                            .addComponent(inputJLabel, GroupLayout.PREFERRED_SIZE, 29, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(83, 83, 83)
                                .addComponent(base64JLabel))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(16, 16, 16)
                                .addComponent(base64JText, GroupLayout.PREFERRED_SIZE, 121, GroupLayout.PREFERRED_SIZE)))
                        .addGap(12, 12, 12)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(hexJText, GroupLayout.PREFERRED_SIZE, 135, GroupLayout.PREFERRED_SIZE)
                            .addComponent(hexJLabel))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(urlEncodeJText, GroupLayout.PREFERRED_SIZE, 123, GroupLayout.PREFERRED_SIZE)
                            .addComponent(urlEncodeJLabel))))
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(htmlEncodeJText, GroupLayout.PREFERRED_SIZE, 115, GroupLayout.PREFERRED_SIZE)
                    .addComponent(htmlEncodeJLabel))
                .addContainerGap())
        )
        return self.handleEncodingPanel


    
    def createHandleDecoding(self):
        def clearText():
            base64JText.text=""
            hexJText.text=""
            urlDecodeJText.text=""
            htmlDecodeJText.text=""
        def handleDecodeButton(event):
            clearText()
            try:
                base64JText.text = base64.b64decode(inputJText.text)
            except:
                pass
            try:
                hexJText.text = binascii.unhexlify(inputJText.text)
            except:
                pass
            try:
                urlDecodeJText.text = urllib.unquote(inputJText.text)
            except:
                pass
            try:
                parser = HTMLParser()
                htmlDecodeJText.text = parser.unescape(inputJText.text)
            except:
                pass
            return
            
        inputJLabel =JLabel()
        base64JText =JTextField()
        decodeButton =JButton("",actionPerformed=handleDecodeButton)
        hexJText =JTextField()
        urlDecodeJText =JTextField()
        htmlDecodeJText =JTextField()
        inputJText =JTextField()
        base64JLabel =JLabel()
        hexJLabel =JLabel()
        urlDecodeJLabel =JLabel()
        htmlDecodeJLabel =JLabel()
        inputJLabel.setText("Input")
        decodeButton.setText("Decode")
        base64JLabel.setText("Base64")
        hexJLabel.setText("Hex")
        urlDecodeJLabel.setText("Url Decode")
        htmlDecodeJLabel.setText("HTML Decode")
        self.handleDecodingPanel=JPanel()
        layout = GroupLayout(self.handleDecodingPanel)
        self.handleDecodingPanel.setLayout(layout)


        layout = GroupLayout(self.handleDecodingPanel)
        self.handleDecodingPanel.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(decodeButton)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, 28, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING, False)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(htmlDecodeJLabel)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(htmlDecodeJText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                            .addComponent(base64JLabel, GroupLayout.Alignment.LEADING)
                            .addComponent(hexJLabel, GroupLayout.Alignment.LEADING)
                            .addComponent(urlDecodeJLabel, GroupLayout.Alignment.LEADING)
                            .addComponent(inputJLabel, GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 47, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(urlDecodeJText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(38, 38, 38)
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                                    .addComponent(base64JText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE)
                                    .addComponent(inputJText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE)
                                    .addComponent(hexJText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE))))))
                .addGap(26, 26, 26))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(277, 277, 277)
                        .addComponent(decodeButton, GroupLayout.PREFERRED_SIZE, 38, GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(16, 16, 16)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(inputJText, GroupLayout.PREFERRED_SIZE, 117, GroupLayout.PREFERRED_SIZE)
                            .addComponent(inputJLabel, GroupLayout.PREFERRED_SIZE, 29, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(83, 83, 83)
                                .addComponent(base64JLabel))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(16, 16, 16)
                                .addComponent(base64JText, GroupLayout.PREFERRED_SIZE, 121, GroupLayout.PREFERRED_SIZE)))
                        .addGap(12, 12, 12)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(hexJText, GroupLayout.PREFERRED_SIZE, 135, GroupLayout.PREFERRED_SIZE)
                            .addComponent(hexJLabel))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(urlDecodeJText, GroupLayout.PREFERRED_SIZE, 123, GroupLayout.PREFERRED_SIZE)
                            .addComponent(urlDecodeJLabel))))
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(htmlDecodeJText, GroupLayout.PREFERRED_SIZE, 115, GroupLayout.PREFERRED_SIZE)
                    .addComponent(htmlDecodeJLabel))
                .addContainerGap())
        )
        return self.handleDecodingPanel




    def createHandleHashing(self):
        def handleHashButton(event):
            md5JText.text = hashlib.md5(binascii.unhexlify(inputJText.text)).hexdigest()
            sha1JText.text = hashlib.sha1(binascii.unhexlify(inputJText.text)).hexdigest()
            sha256JText.text = hashlib.sha256(binascii.unhexlify(inputJText.text)).hexdigest()
            sha512JText.text = hashlib.sha512(binascii.unhexlify(inputJText.text)).hexdigest()
            return
        inputJLabel =JLabel()
        md5JText =JTextField()
        hashButton =JButton("",actionPerformed=handleHashButton)
        sha1JText =JTextField()
        sha256JText =JTextField()
        sha512JText =JTextField()
        inputJText =JTextField()
        base64JLabel =JLabel()
        hexJLabel =JLabel()
        urlEncodeJLabel =JLabel()
        htmlEncodeJLabel =JLabel()
        inputJLabel.setText("Input Hex)")
        hashButton.setText("Hash")
        base64JLabel.setText("md5")
        hexJLabel.setText("SHA1")
        urlEncodeJLabel.setText("SHA256")
        htmlEncodeJLabel.setText("SHA512")
        self.handleHashingPanel=JPanel()
        layout = GroupLayout(self.handleHashingPanel)
        self.handleHashingPanel.setLayout(layout)


        layout = GroupLayout(self.handleHashingPanel)
        self.handleHashingPanel.setLayout(layout)
        layout.setHorizontalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(hashButton)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, 28, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING, False)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(htmlEncodeJLabel)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(sha512JText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                            .addComponent(base64JLabel, GroupLayout.Alignment.LEADING)
                            .addComponent(hexJLabel, GroupLayout.Alignment.LEADING)
                            .addComponent(urlEncodeJLabel, GroupLayout.Alignment.LEADING)
                            .addComponent(inputJLabel, GroupLayout.Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 47, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(sha256JText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(38, 38, 38)
                                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING, False)
                                    .addComponent(md5JText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE)
                                    .addComponent(inputJText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE)
                                    .addComponent(sha1JText, GroupLayout.PREFERRED_SIZE, 735, GroupLayout.PREFERRED_SIZE))))))
                .addGap(26, 26, 26))
        )
        layout.setVerticalGroup(
            layout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(277, 277, 277)
                        .addComponent(hashButton, GroupLayout.PREFERRED_SIZE, 38, GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(16, 16, 16)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(inputJText, GroupLayout.PREFERRED_SIZE, 117, GroupLayout.PREFERRED_SIZE)
                            .addComponent(inputJLabel, GroupLayout.PREFERRED_SIZE, 29, GroupLayout.PREFERRED_SIZE))
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGap(83, 83, 83)
                                .addComponent(base64JLabel))
                            .addGroup(layout.createSequentialGroup()
                                .addGap(16, 16, 16)
                                .addComponent(md5JText, GroupLayout.PREFERRED_SIZE, 121, GroupLayout.PREFERRED_SIZE)))
                        .addGap(12, 12, 12)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(sha1JText, GroupLayout.PREFERRED_SIZE, 135, GroupLayout.PREFERRED_SIZE)
                            .addComponent(hexJLabel))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(sha256JText, GroupLayout.PREFERRED_SIZE, 123, GroupLayout.PREFERRED_SIZE)
                            .addComponent(urlEncodeJLabel))))
                .addGap(12, 12, 12)
                .addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(sha512JText, GroupLayout.PREFERRED_SIZE, 115, GroupLayout.PREFERRED_SIZE)
                    .addComponent(htmlEncodeJLabel))
                .addContainerGap())
        )
        return self.handleHashingPanel
