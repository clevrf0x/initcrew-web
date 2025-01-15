import BlogPost from '@/components/custom/blog';
import Footer from '@/components/custom/footer';
import NavMenu from '@/components/custom/nav-menu';

export default function KeralaPoliceYoutubeHackBlog() {
  const frontmatter = {
    title: 'Kerala Police Youtube Takeover Incident Analysis',
    date: '2023-01-18',
    tags: ['Incident Analysis', 'Malware Analysis', 'Reverse Engineering', 'Vidar'],
    authors: ['Akash Sebastian', 'Nashid P', '5P34R'],
  };

  const content = `
  On Tuesday morning 17 January 2023, we came across an interesting message in our community group. It was regarding the Kerala Police YouTube channel, which had apparently been hacked. At first, we found it hard to believe and thought it might just be a rumor, but a quick search confirmed that it was true.

  [![Initcrew Community Chat](/images/posts/kerala-police-youtube-takeover/community-chat.webp)](/images/posts/kerala-police-youtube-takeover/community-chat.webp)
  
  This incident quickly became a hot topic of discussion on that day.

  The hacker had uploaded several videos promoting cracked software, along with links (which were likely malware, as we will discuss later in this post). The hacker also changed the names of existing videos on the channel.
  
  [![Kerala Police YouTube Channel](/images/posts/kerala-police-youtube-takeover/youtube-channel.webp)](/images/posts/kerala-police-youtube-takeover/youtube-channel.webp)
  
  Reading the comments on the videos, it was clear that many people were confused and thought the police themselves had uploaded the videos. However, some people understood that the account had been hacked and began sharing awareness about the incident. The comment section also became a hot topic of discussion.

  [![Kerala Police YouTube Channel Comments](/images/posts/kerala-police-youtube-takeover/yt-comments.webp)](/images/posts/kerala-police-youtube-takeover/yt-comments.webp)

  At first, we ignored the incident and went back to our daily routine. But after noticing the embedded files that the hacker had included in the videos, our curiosity and interest were triggered. Although we knew that the files were likely malware, we were still curious about their actions and behaviors. So, we downloaded them onto our system to investigate further.

  <br />

  <ol class="list-decimal pl-8 space-y-4">
      <li class="transition-colors duration-200 break-all"><a href="https://download2302.mediafire.com/bojtloki32sg/5j44i2d8xmmfoyb/AUTODESK+3DS+MAX.rar">https://download2302.mediafire.com/bojtloki32sg/5j44i2d8xmmfoyb/AUTODESK+3DS+MAX.rar </a></li>
      <li class="transition-colors duration-200 break-all"><a href="https://download2363.mediafire.com/y7ktk2u0b80g/obogr4njpashfth/Ccleaner+Pro.rar"> https://download2363.mediafire.com/y7ktk2u0b80g/obogr4njpashfth/Ccleaner+Pro.rar </a></li>
      <li class="transition-colors duration-200 break-all"><a href="https://download2363.mediafire.com/ccq2anyt4ztg/r2junum6h49v4iq/Davinci+Resolve+18.rar">https://download2363.mediafire.com/ccq2anyt4ztg/r2junum6h49v4iq/Davinci+Resolve+18.rar</a></li>
  </ol>

  All the archives were password protected and password was shared in the description of the videos.<br />
  Password: **1234**

  We checked all samples and they were all same. So we chose a random sample namely AUTODESK for the showcase.<br />
  Extracting the archive gives a Setup.exe file and About folder. The About folder had lots of windows group-policy files.

  [![AUTODESK 3DS MAX](/images/posts/kerala-police-youtube-takeover/extract.webp)](/images/posts/kerala-police-youtube-takeover/extract.webp)

  We tried running the program in a windows 11 virtual machine while keeping the windows defender ON. Defender didn’t picked any suspicious activities. Meanwhile, all the network requests were logged using fiddler tool.

  Here is the overview of network requests<br />

  <ul class="list-disc pl-8 space-y-3">
      <li>
          Initially, the program make a request to telegram channel named <span class="font-bold">jetbim</span>.
      </li>
      <li>
          It then grabs an IP from the telegram channel description and make request to <span class="font-bold">754</span> endpoint.
      </li>
      <li>
          Finally downloads a zip file named pack.zip
      </li>
  </ul>

  [![Vidar Telegram Group](/images/posts/kerala-police-youtube-takeover/vidar-telegram.webp)](/images/posts/kerala-police-youtube-takeover/vidar-telegram.webp)

  [![Fiddler Network Requests](/images/posts/kerala-police-youtube-takeover/traffic.webp)](/images/posts/kerala-police-youtube-takeover/traffic.webp)

  Telegram channel link : [https://t.me/jetbim](https://t.me/jetbim)

  In this, the threat actor created Telegram channel with the IP address of C2 in the channel description. \`liber http://65.109.200.241:80\`

  this IP is then used to download the files<br />
  Then it sends a request to : http://65.109.200.241/754

  [![Vidar 754 Request](/images/posts/kerala-police-youtube-takeover/vidar-754.webp)](/images/posts/kerala-police-youtube-takeover/vidar-754.webp)

  and response contains :

  ~~~powershell
  d8 1,1,1,1,1,cc332423b30ba3c7a578f3d40d62c006,1,0,1,1,0,Default;%DOCUMENTS%\\;*.txt;50;true;movies:music:mp3:exe;recent;%RECENT%\\;*.txt;50;false;movies:music:mp3:exe;desktop;%DESKTOP%\\;*.txt;50;true;movies:music:mp3:exe; 0
  ~~~
  It is used for finding files with sensitive content.

  [![Vidar H2](/images/posts/kerala-police-youtube-takeover/vidar-h2.webp)](/images/posts/kerala-police-youtube-takeover/vidar-h2.webp)

  When we tried to access the IP, we received a 403 error for unauthorized access. After analyzing the Fiddler logs to see how the executable downloads the file, we noticed something interesting.
  
  [![Vidar Pack.zip](/images/posts/kerala-police-youtube-takeover/pack.webp)](/images/posts/kerala-police-youtube-takeover/pack.webp)

  The Fiddler request only contains the host address and location, nothing else, even though it is a web request. By removing the user agent from our request, we were able to read the contents of the website. Similarly, we downloaded the __pack.zip__ file onto our system for further analysis.
  
  [![Vidar Pack.zip](/images/posts/kerala-police-youtube-takeover/vidar1.webp)](/images/posts/kerala-police-youtube-takeover/vidar1.webp)

  **nss3.dll** Network System Services Library <br />
  **freebl3.dll** Freebl Library for the NSS <br />
  **mozglue.dll** Mozilla Browser Library <br />
  **msvcp140.dll** Visual C++ Runtime 2015 <br />
  **softokn3.dll** Mozilla Browser Library <br />
  **vcruntime140.dll** Visual C++ Runtime 2015

  These are the dll required for the program. These dlls are then dynamically loaded to collect browser history, cookies etc.

  [![PEStudio](/images/posts/kerala-police-youtube-takeover/pestudio.webp)](/images/posts/kerala-police-youtube-takeover/pestudio.webp)

  Finally, the program sends the collected data to the Command and Control (C2) server and then proceeds to self-destruct, deleting all associated DLLs and related files in the process. This makes it difficult for authorities to trace the origin of the attack and identify the hacker responsible.

  We used network scanners to scan the Command and Control (C2) server to check for any services that might be running. Unfortunately, we didn't find any open ports other than SSH.

  [![NMAP Vidar](/images/posts/kerala-police-youtube-takeover/nmap-vidar.webp)](/images/posts/kerala-police-youtube-takeover/nmap-vidar.webp)

  After researching the pattern and behavior of the malware, we discovered that it is a **Vidar Malware**, a stealer software designed to collect and exfiltrate sensitive information from the users to the Command and Control (C2) server controlled by the attacker.

  For more information about the **Vidar Malware**, you can check out the blog by Fumko.
  https://fumik0.com/2018/12/24/lets-dig-into-vidar-an-arkei-copycat-forked-stealer-in-depth-analysis/

  In conclusion, the programs used in this hack are highly malicious information stealers. We speculate that the Kerala Police YouTube channel got hacked through phishing or possibly by running a similar program. It is advisable to avoid installing cracked software in order to maintain the safety and security of your own systems. Users should also be vigilant and aware of the risks associated with clicking on suspicious links or installing unknown software.
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
