import speech_recognition as sr 
import pyttsx3 as p
import os 


intro = '''     
      ::::    :::  :::   :::      :::    ::::::::: ::::::::: ::::::::::::::::::: 
     :+:+:   :+: :+:+: :+:+:   :+: :+:  :+:    :+::+:    :+::+:       :+:    :+: 
    :+:+:+  +:++:+ +:+:+ +:+ +:+   +:+ +:+    +:++:+    +:++:+       +:+    +:+  
   +#+ +:+ +#++#+  +:+  +#++#++:++#++:+#++:++#+ +#++:++#+ +#++:++#  +#++:++#:    
  +#+  +#+#+#+#+       +#++#+     +#++#+       +#+       +#+       +#+    +#+    
 #+#   #+#+##+#       #+##+#     #+##+#       #+#       #+#       #+#    #+#     
###    #######       ######     ######       ###       #############    ###      



            Version    : 1.0
            Author     : Orhan YILDIRIM
            Medium     : @orhan_yildirim
            Linkedin   : www.linkedin.com/in/orhan-yildirim
            License    : MIT License
            Note       : Who's up!

            You can use "help" command for access help section.
'''
print(intro)


engine = p.init()
voices = engine.getProperty('voices')
#engine.setProperty('voice', voices[0].id)  # changing index, changes voices. 0 for male
engine.setProperty('voice', voices[1].id)  # changing index, changes voices. 1 for female
engine.setProperty('rate', 140)

r = sr.Recognizer()
def speak(str):
    engine.say(str)
    engine.runAndWait()

print('[nMapper] Starting...')
speak('Starting nMapper!')




with sr.Microphone() as source:
    speak('nMapper, is at your service')
    print('[nMapper] You can speak...')
    text = r.listen(source)

    try:
        recognized_text = r.recognize_google(text)
        print('[nMapper] Your command is: ', recognized_text)
    except sr.UnknownValueError:
        print("[nMapper] Unknown command!")
    except sr.RequestError as e:
        print("")


if 'help' in recognized_text:
    os.system('help')

if 'who' in recognized_text:
    os.system('whoami')
