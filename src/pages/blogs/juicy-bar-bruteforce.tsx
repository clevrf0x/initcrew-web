import BlogPost from '@/components/custom/blog';
import Footer from '@/components/custom/footer';
import NavMenu from '@/components/custom/nav-menu';

export default function JuicyBarBruteforceBlog() {
  const frontmatter = {
    title: 'Android CTF Juicy Bar::Bruteforce',
    date: '2024-04-21',
    tags: ['Android Security', 'Juicy Bar', 'Reverse Engineering', 'Writeup', 'Frida'],
    authors: ['Ajin Deepak'],
    canonicalUrl: 'https://ad2001.com/blog/juicy-bar-bruteforce',
  };

  const content = `Hey all,

Let's continue with our walkthrough of Juicy Bar. If you're new here, try  checking out other blogs and take the challenge before reading this.

https://juicy.barsk.xyz/

Also, In this level we only need to find one flag.

## Challenge

Let's see the hints.

![](/images/posts/juicy-bar/brute-force/1.webp)

It's a very easy challenge. We need to brute a 4 digit pin to solve the challenge. We have a dialogue box to enter the pin.

![](/images/posts/juicy-bar/brute-force/2.webp)

Let's use jadx and find out the responsible method for validating the pin.

![](/images/posts/juicy-bar/brute-force/3.webp)

This one method looks like the one we are interested in. So let's use frida and try to brute force it. If we enter the correct pin the method will return \`Validation succeeded, flag printed to logcat\`

![](/images/posts/juicy-bar/brute-force/4.webp)

So we can create a frida script to  try PINs from 0000 to  9999. When the function returns the message "Validation succeeded, flag  printed to logcat," we will have successfully identified the correct PIN.

~~~javascript
Java.perform(function () {
 
    var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    var BruteForce = Java.use('xyz.barsk.juicy.levels.dynamic.BruteForce');
    var bruteInstance = BruteForce.$new();

    var successMessage = "Validation succeeded, flag printed to logcat";

    for (var i = 0; i < 10000; i++) {
        var pin = ("0000" + i.toString()).slice(-4); // Ensure the PIN is a 4-digit string
        var result = bruteInstance.inputProvided(pin, context);

        if (result.indexOf(successMessage) !== -1) {
            console.log('[*] Success with PIN:', pin);
            console.log('[*] Message:', result);
            break; 
        }
    }
});

~~~

I won't be explaining the frida script. If you are new to frida please check out my repo.

https://github.com/DERE-ad2001/Frida-Labs

![](/images/posts/juicy-bar/brute-force/5.webp)

Nice we got the pin. It's 8472. Let's check if this is the correct pin.

![](/images/posts/juicy-bar/brute-force/6.webp)

We got the flag. Thanks for reading and see you in the next one.
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
