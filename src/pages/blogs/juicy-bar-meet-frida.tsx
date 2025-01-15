import BlogPost from '@/components/custom/blog';
import Footer from '@/components/custom/footer';
import NavMenu from '@/components/custom/nav-menu';

function JuicyBarMeetFridaBlog() {
  const frontmatter = {
    title: 'Android CTF Juicy Bar::Meet Frida',
    date: '2024-04-07',
    tags: ['Android Security', 'Juicy Bar', 'Reverse Engineering', 'Writeup', 'Frida'],
    authors: ['Ajin Deepak'],
  };

  const content = `Hey all,

Let's continue with our walkthrough of Juicy Bar. If you're new here, try checking out other blogs and take the challenge before reading this.

https://juicy.barsk.xyz/

Also, this level contains challenges that can be solved using Frida. If you are new to Frida, please check out my repository and try this challenge.

To complete this frida challenge we need to find three flags. Let's start with the first flag.

### Flag One

![](/images/posts/juicy-bar-meet-frida/1.webp)

So let's load the apk into jadx and see the decompilation for this level.

![](/images/posts/juicy-bar-meet-frida/2.webp)
![](/images/posts/juicy-bar-meet-frida/3.webp)

The hints says that this method is called but the return value is never used. The return value is of type string so i guess it should be the flag. So what we can do is we can hook this method and get the flag.

First let's get the package name of this app.

~~~powershell
PS C:\\Users> frida-ps -Uai
 PID  Name                   Identifier
4  ---------------------  -------------------------------
5777  Calendar               com.android.calendar
5576  Clock                  com.android.deskclock
7801  Juicy Bar              xyz.barsk.juicy
6085  LinkedIn               com.linkedin.android
5606  Phone                  com.android.dialer
   -  Amaze                  com.amaze.filemanager
   -  BlogFuzz               qb.blogfuzz
   -  Camera                 com.android.camera2
   -  Contacts               com.android.contacts
   -  DNS66                  org.jak_linux.dns66
   -  Dev Tools              com.android.development
   -  Files                  com.android.documentsui
   -  Gallery                com.android.gallery3d
   -  InsecureShop           com.insecureshop
   -  Messaging              com.android.messaging
   -  My Application         com.juicy.myapplication
   -  My Application 3       xyz.barsk.juicy_vault
   -  Search                 com.android.quicksearchbox
   -  Service                com.android.service
   -  Settings               com.android.settings
   -  SignatureVerification  com.juicy.signatureverification
   -  Superuser              com.genymotion.superuser
   -  Tweeter Clone          com.development.tweeterclone
   -  WebView Shell          org.chromium.webview_shell
PS C:\\Users>
~~~

Let's start this app with frida.

![](/images/posts/juicy-bar-meet-frida/4.webp)

Now let's write the frida script to hook this. I will provide you a template for reference.

~~~javascript
Java.perform(function() {

  var <class_reference> = Java.use("<package_name>.<class>");
  <class_reference>.<method_to_hook>.implementation = function(<args>) {

    /*
      OUR OWN IMPLEMENTATION OF THE METHOD
    */

  }

})
~~~

- Package name : \` xyz.barsk.juicy.levels.dynamic\`
- Class : \`FridaIntro\`
- Method to hook : \`getFlag1\`

Let's write the actual script.

![](/images/posts/juicy-bar-meet-frida/5.webp)

Okay now we can trigger this method in the application.

![](/images/posts/juicy-bar-meet-frida/6.webp)
![](/images/posts/juicy-bar-meet-frida/7.webp)

Nice we got the first flag. Let's find the second one.

### Flag Two

![](/images/posts/juicy-bar-meet-frida/8.webp)

Let's use jadx to see what's happening.

~~~java
private final boolean printFlag2(Context context) {
    Log.i("Frida", "member: " + this.member + ", staticMember: " + staticMember);
    if (this.member == 23 && staticMember == 584 && i.a(getFlag1(context), "Flaggy McFlagface")) {
        d.p(16);
        $$p(context, o.U(d.F(2600, 'c', b.d(new StringBuilder("880"), this.member, "066"), Long.toString(4506044005L, 16), ("FB" + staticMember + 'A').toLowerCase(Locale.ROOT), new StringBuilder((CharSequence) "49ac1e4db3").reverse().toString()), "", null, null, null, 62));
        return true;
    }
    return false;
}
~~~

This is the code responsible for getting the second flag. If this returns true the flag will get logged. So let's look at the condition we have to satisfy to get the flag.

~~~java
if (this.member == 23 && staticMember == 584 && i.a(getFlag1(context), "Flaggy McFlagface")) {}
~~~

The condition in the given code snippet involves three separate checks combined with the logical AND operator (\`&&\`). This means that for the \`if\` statement's body to be executed, all three conditions must be true. Here's an explanation of each part:

1. **\`this.member == 23\`**:
    - This condition checks if the \`member\` variable of the current object (\`FridaIntro \`) has a value of \`23\`.
2. **\`staticMember == 584\`**:
    - This condition checks if the \`staticMember\` variable has a value of \`584\`. It's a static variable.
3. **\`i.a(getFlag1(context), "Flaggy McFlagface")\`**:
    - This checks if the return value of \`getFlag1()\` is \`Flaggy McFlagface\`.

If any of these conditions are  met we will get the second flag. So let's write a frida script to do this. I won't be explaining this script as i have explained all of these stuff in github repo. Well if you still want to solve this use chatgpt. It's very easy.

~~~java
Java.perform(function () {
    var FridaIntro = Java.use("xyz.barsk.juicy.levels.dynamic.FridaIntro");

    // Set the static member 'staticMember' to 584
    FridaIntro.staticMember.value = 584;

    // Hook the getFlag1 method to return "Flaggy McFlagface"
    FridaIntro.getFlag1.implementation = function(context) {
        return "Flaggy McFlagface";
    };

    // Use onMatch to modify instance variable 'member' when an instance is matched
    Java.choose("xyz.barsk.juicy.levels.dynamic.FridaIntro", {
        onMatch: function(instance) {
            instance.member.value = 23;
            console.log("Instance modified: member set to 23");
        },
        onComplete: function() {
            console.log("Finished searching for instances.");
        }
    });
});
~~~

The code above was generated by ChatGPT. You may need to tweak it occasionally. Let's try it now.

![](/images/posts/juicy-bar-meet-frida/9.webp)

Let's see if we get the flag or not.

![](/images/posts/juicy-bar-meet-frida/10.webp)

Nice we got the second flag.

### Flag Three

![](/images/posts/juicy-bar-meet-frida/11.webp)

Let's take a look at the code using jadx.

~~~java
private final boolean printFlag3(Context context) {
    String uuid = UUID.randomUUID().toString();
    if (i.a(uuid, "totally not a random UUID")) {
        $$p(context, "22008980232" + uuid.charAt(17) + "ec" + uuid.charAt(17) + uuid.charAt(17) + "46c011905996193004644264eb3bf" + uuid.charAt(3) + "38a7bd2ddf050");
        return true;
    }
    return false;
}
~~~

The \`printFlag3\` method generates a random UUID and checks if it is equal to the string "totally not a random UUID". If they are the  same, this method will return true, allowing us to obtain the flag. The \`UUID.randomUUID()\` method generates a random UUID object, which is then converted to a string every time using the \`toString()\` method. To capture the flag, we can hook \`toString\`method and make it return the string "totally not a random UUID". Let's write the Frida script for this.

~~~java
Java.perform(function () {
    var UUID = Java.use('java.util.UUID');
    UUID.toString.implementation = function () {
        return "totally not a random UUID";
    };
});
~~~

This frida script hooks the \`toString()\` and returns the string \`totally not a random UUID\`. This will satisfy the if condition and we will get the flag. Let's try this.

![](/images/posts/juicy-bar-meet-frida/12.webp)
![](/images/posts/juicy-bar-meet-frida/13.webp)

Alright we got the third flag. Thanks for reading.

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

export default JuicyBarMeetFridaBlog;
