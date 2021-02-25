"""
                    Rochester Institute of Technology Dubai
                    
                    Information Security Programming 201.600

                                Assignment II


                                Chatbot Server
                                

Language: Python 3

Group: Rashed Alnuman, Ammar Albanna, Komil mamasaliev Mohammad Mohammad

Description: chatbot server, recieves questions and returns html
             pages of questions requested by the client

"""





try:

    import sys
    import socket
    import random
    import string
    import logging
    import datetime
    import threading
    from pyDes import *
    from time import sleep
    

    import urllib.request
    import urllib.parse
    import urllib.error

    from urllib.request import  urlopen

except ImportError as IE:
    print(IE, "\n Missing modules to run Gary, please install the modules first then run")
    sys.exit(1)


# setting up logging and  using lambda to log
logging.basicConfig(filename = "Server_Error_Logs.log", filemode = 'w', format = '%(message)s', level = logging.ERROR)
logger = lambda msg : logging.error(msg)


    

def packetChecker(ext):

    """
    Uses keywords that are found in the question by the user to match with
    its respective packet type and returns it with some information, in
    case its unrecognisable returns error code 1
    """

    err_code1 = "ERROR CODE 1 : I Could not recognise the packet type"
    
    packet_types = {"hello": "Greetings (Packet-Type: GR)",
                    "what": "Information Response (Packet-Type: IR)",
                    "where": "Location Response (Packet-Type: LR)",
                    "when": "Time Response (Packet-Type: TR)",
                    "search": "Google Results (Packet-Type: RR)",
                    "permission": "Granting permission using authentication Credentials (Packet-Type: PR)",
                    "end": "Session closing packet, ending communication (Packet-Type: CP)"}
    try:
        return packet_types[[(i) for i in packet_types.keys() if i in ext.lower()][0]]
    
    except IndexError as IE: # if packet type couldnt be recognised, return error code 1
        logger(err_code1) # log the error to file
        return err_code1
    






def responder(packet, connection):

    """
    Called by the server connection thread, retrieves the TTP packet type
    from packet checker function and responds accordingly, logs and responds
    to user in case of errors. Does not return anything, sends directly to client
    """

    # Three possible exceptions that could occur during runtime
    err_code1 = "ERROR CODE 1 : I Could not recognise the packet type"
    err_code2 = "ERROR CODE 2 : I am unable to answer the question"
    err_code3 = "ERROR CODE 4 : I was unable to connect to the internet to process your search"

    info = packetChecker(packet)            # information about packet type
    packet_type = info[-3:-1]               # actual type of packet
    command = packet.split(',')[1].lower()  # the question by the user

    packet_info = DEScrypt(info, 1, session_key) # encrypt the packet info
    connection.send(packet_info)                 # send the client the packet info and type

    if info == err_code1: # alert client of unrecognisable packet type and then send it
        msg = "Provide a valid command"
        msg1 = DEScrypt(msg, 1, session_key)
        connection.send(msg1)

    
            
    if packet_type == "GR": # greeting packet, greet user back
        
        response = "Hello user, my name is Gary the chatbot"
        greetings_response = DEScrypt(response, 1, session_key)
        connection.send(greetings_response)
        
     

    elif packet_type == "IR": # information response packet, asks something, replies to user if answer is avilable
        
        if "time" in command: # tell user the time
            info_response = DEScrypt(datetime.datetime.now().strftime("%H:%M:%S"), 1, session_key)
            connection.send(info_response)

        elif "date" in command: # tell user the date
            info_response = DEScrypt(datetime.datetime.now().strftime("%Y-%m-%d"), 1, session_key)
            connection.send(info_response)
            
        elif "life" in command: # tell user the answer the meaning of life
            info_response = DEScrypt("The answer to life is 42", 1, session_key)
            connection.send(info_response)


        elif "is" in command:
            splitting = command.split("is")
            mathing = splitting[1].strip("'")

            try:
                answer = eval(mathing)
                info_response = str(answer)
            except:
                info_response = err_code2

            connection.send(DEScrypt(info_response, 1, session_key))

        
        
        else:
            exc_packet = err_code2
            logger(err_code2)
            connection.send(DEScrypt(exc_packet, 1, session_key))
        
    elif packet_type == "LR": # location response, tell the client in which continent is the country

        asia =          ["russia", "china", "japan", "india", "malaysia", "jordan", "pakistan", "palestine", "lebanon", "uae", "phillipines"]
        europe =        ["sweden", "denmark", "spain", "czech", "italy", "portugal", "sweden", "denmark", "germany"]
        north_america = ["usa", "canada"]
        south_america = ["argentina", "chile", "brazil", "mexico", "venzuela", "colombia", "puerto rico"]
        africa =        ["egypt", "nigeria", "tunis", "algeria", "sudan", "south africa"]
        continents =    ["asia", "europe", "north america", "south america", "africa"]
        index = -1

        try:
            for contin in asia, europe, north_america, south_america, africa:
                index += 1
                for coun in contin:
                    if coun in command.lower():
                        country = coun
                        continent = continents[index]

            location_packet = DEScrypt(country + " is in " + continent, 1, session_key)
            connection.send( location_packet )
            

        except: # country not found then gary doesnt know where it is 
            msg = DEScrypt( err_code2 + ", I dont know where that is :(", 1, session_key) 
            logger(err_code2)
            connection.send(msg)
            return None



    elif packet_type == "TR":  # time response, tell client the date of an event

        if "ramadan" in command:
            time_packet = "Monday, 12 April"
        elif "christmas" in command:
            time_packet = "Friday, 25 December"
        elif "eid" in command and "adha" in command:
            time_packet = "Monday, 19 July"
        elif "new" in command and "year" in command:
            time_packet = "Friday, 1 January"
        else:
            time_packet = err_code2 + ", I do not know when that is :("
            logger(err_code2)
            
        connection.send(DEScrypt(time_packet, 1, session_key))
            
    

    elif packet_type == "RR":  # client wants search result, pass it to google search function

        googleSearch(connection, command)

    elif packet_type == "PR": # give permission to the client even if he wants to destroy the world np

        permission_packet = "Gary the chatbot grants you the requested permissions"
        connection.send(DEScrypt(permission_packet, 1, session_key))

    elif packet_type == "CP": # CP packet declares the closing phase, communication ends here as declared by client

        try:
            closing_msg = "Thank you for chatting Gary the chatbot, please dont come back"
            connection.send(DEScrypt(closing_msg, 1, session_key))
            connection.close() # close the connection
        except:
            connection.close()



def DEScrypt(msg, mod, key):

    """
    Uses Triple DES algorithm to encrypt string or bytes passed to function,
    mod defines whether to encrypt or decrypt and key is the key (obviously)
    to either encrypt or decrypt. if encryption is false meaning no encryption
    is required by the client-user then it will return a byte format of the
    original string
    """
    
    if encryption:  # dont encrypt or decrypt if encryption doesnt exist
        
      
        cipher = des(key, CBC, "\0\0\0\0\0\0\0\0", pad = None, padmode = PAD_PKCS5)

        if mod == 1:
            encrypted_data = cipher.encrypt(msg) 
            return encrypted_data
        

        elif mod == 2:
            decrypted_data = cipher.decrypt(msg)
            return decrypted_data

    else:
        return bytes(str(msg), "utf-8")


def googleSearch(connection, ques):

    """
    Called by the responder function, uses urllib to search for the client
    question,recieves the html page from the Google server and then sends the
    first 50 characters of the result. Adapts to correctly search for either
    one word or phrase.
    """


    try:

        ques = ques.replace("search", '') # clean out the words search and for from the question
        ques = ques.replace("for", '')
        question_parts = ques.split()
        question = ''
        count = 0
        
        for word in question_parts: 
            question += word
            count += 1

            if len(question_parts) > 1:        # URL uses + to chain keywords, this constructs that format
                if count < len(question_parts):
                    question += '+'
            
        url = 'https://www.google.com/search?q=' + question # now, with the below headers, we defined ourselves as a simpleton who is # still using internet explorer.
        print(url)
        headers = {}
        headers['User-Agent'] = "Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.27 Safari/537.17" # bamboozle the Google server into thinking this is a browser request
        req = urllib.request.Request(url, headers = headers) # adding our request header
        resp = urllib.request.urlopen(req)
        respData = resp.read()[:52] #read the first 52 characters 
        connection.send( DEScrypt(respData, 1, session_key)) # pass it down through encryptor and send to client

    except Exception as e:
        print(str(e))
        print(e.getheaders())# reading response headers fields
        resp = "ERROR CODE 3 : I was unable to connect to the internet to process your search"
        logger(err_code3)  # log event of error
        connection.send(DEScrypt(resp, 1, session_key)) # inform user that a error has occured in the process



def ServerConnection(connection, address):

    """
    Thread function created by main, connection and address are passed down as parameters,
    then using connection recieves packets from client. Analyzes SS packets to determine
    if connection is requested with or without encryption, generates random sesssion key
    and encrypts with public key to send to user. Runs a while loop to recieve questions
    from the client and passes them down to responder to handle. doesn't return anything
    """
    
    
    with connection:
        
        print(address, "has connected to the server...")

        global encryption
        global session_key
        
        encryption = False
        
        
        while True:

            
            data = connection.recv(1024)    # recieve bytes data
            str_data = data.decode("utf-8") # translates bytes from socket stream to string
            print(str_data)

            components = str_data.split(',')
            packet_type = components[0]
         

            if packet_type == "SS":

                enc = components[-1]
                
                if enc == '1':         #unpacking the security packet and extracting information
                    
                    encryption = True
                    enc_pack = connection.recv(1024)
                    print(enc_pack)
                    enc_pack_str = enc_pack.decode("utf-8")
                    enc_components = enc_pack_str.split(',')
                    print(enc_components)
                    
                    user_pass = enc_components[-1]
                    authorization = enc_components[1]
                    username = user_pass.split(':')[0]
                    password = user_pass.split(':')[1]
                    print(username, "  ", password)

                    session_key = ''.join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k = 8))# generating a random 8 character session key
                    print(session_key)
                    
                    session_key_packet = DEScrypt( "SK," + session_key, 1, public_key)
                    connection.send(session_key_packet)
                    print("التشفير يعمل أصدقائي")
                    
                else:
                    session_key = ""

                
            setup = bytes("CC", encoding = "utf-8")
            connection.send(setup)

            try:
                while True:

                

                    data = connection.recv(1024)

                    if not data: # if client closes then end execution of thread
                        break
                    
                    decrypted_data = DEScrypt(data, 2, session_key)
                    command_packet = decrypted_data.decode("utf-8")
                    responder(command_packet, connection)

            except:
                print(str(address) + " Disconnected...")
                return None
                
            
            
                
                
                
            
                
        
def main():

    """
    Main function, static host, port and public key. Creates TCP socket object sock
    and binds to host,port tuple. after listening and connecting to a client, creates
    a connection thread and sends the client connection to that thread and gets ready
    to accept a new client.
    """

    
    host = '127.0.0.1'  # localhost
    port= 65432        # Listening on this specific port

    global public_key
    public_key = "1a2b3c4d"


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        sock.bind((host, port))

        while True:
            
            print("Socket bounded succesffuly...")
            print("Awaiting connection...\n")
        
            sock.listen()
        
            connection, address = sock.accept() # when making multi threaded server, we will pass the connection
            msg = connection, " connected"      # and address to the thread function and then wait for another 
                                                # new socket connection from another client
        
       
            socket_thread = threading.Thread(target = ServerConnection, args=(connection, address,))
            msg = "started connection thread for ", connection
            socket_thread.start()
            


     
main()









                

#
