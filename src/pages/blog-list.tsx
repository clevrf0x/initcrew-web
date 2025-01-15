import BlogCard from '@/components/custom/blog-card';
import NavMenu from '@/components/custom/nav-menu';
import { Separator } from '@/components/ui/separator';
import { useNavigate } from 'react-router-dom';

function BlogList() {
  const navigate = useNavigate();
  return (
    <div className='min-h-screen flex flex-col px-[5%] pt-2 lg:px-[10%] lg:pt-5'>
      <div className='flex-grow'>
        <NavMenu />
        <div className='mt-12 flex flex-col justify-center items-center '>
          <h1 className='text-3xl text-center font-bold uppercase'>Blogs</h1>
          <Separator className='my-2 mb-10 w-[50px] bg-gray-500' />
          <div />
          <div className='mb-10 grid grid-cols-1 gap-6 lg:grid-cols-2'>
            {/* <BlogCard
              title='Android CTF Juicy Bar::Bruteforce'
              authors={[{ name: 'Jane Doe', avatar: '/jane-avatar.jpg' }, { name: 'John Smith' }]}
              publishedDate={new Date('2024-01-13')}
              description='Explore the latest trends and best practices in modern web development. From React to TypeScript, we cover everything you need to know to stay ahead in the fast-paced world of web development.'
              onReadMore={() => console.log('Navigating to blog post...')}
            /> */}
            <BlogCard
              title='Kerala Police Youtube Takeover Incident Analysis'
              authors={[
                { name: 'Akash Sebastian', avatar: '/images/authors/akash-profile.webp' },
                { name: 'Nashid P' },
                { name: '5P34R' },
              ]}
              publishedDate={new Date('2023-01-18')}
              description={`In this blog, we analyze the high-profile hacking incident of the Kerala Police YouTube channel on January 17, 2023. The hackers uploaded malicious videos promoting cracked software and embedded malware-laden links, tricking unsuspecting viewers.
                            The blog delves into the behavior of the malware, from its initial network requests via Telegram to its data exfiltration to a Command and Control (C2) server, followed by a self-destructive cleanup process. By reverse engineering the attack, the blog identifies the malware as Vidar, a notorious information stealer.`}
              onReadMore={() => navigate('/blogs/kerala-police-youtube-takeover')}
            />
            <BlogCard
              title='From Tracing to Patching using Frida'
              authors={[{ name: 'Ajin Deepak', avatar: '/images/authors/ad-profile.webp' }]}
              publishedDate={new Date('2024-04-21')}
              description={`Learn how to leverage Frida's powerful tracing capabilities to reverse engineer and modify Android applications, demonstrated through a case study with Mini Militia Classic. This article explores tracing, disassembly, and live instrumentation to achieve hacks like unlimited bullets and jetpack fuel.`}
              onReadMore={() => navigate('/blogs/frida-tracing-and-patching')}
            />
            <BlogCard
              title={`A Noob's Guide to ARM Exploitation: Learn, Practice, Master`}
              authors={[{ name: 'Ajin Deepak', avatar: '/images/authors/ad-profile.webp' }]}
              publishedDate={new Date('2024-10-27')}
              description={`Embark on a journey into the fascinating world of ARM exploitation with Ajin Deepak, a passionate security researcher from mobilehackinglabs. This beginner-friendly guide compiles practical insights and hands-on writeups covering topics like stack buffer overflows, ROP chains, heap exploitation, ARM64 techniques, and more.
                            With a focus on clarity and accessibility, this book is perfect for anyone with a background in computer science, a grasp of C programming, and an interest in low-level exploitation. Whether you're new to ARM or want to refine your skills, this ever-evolving resource offers valuable guidance to help you grow.`}
              onReadMore={() =>
                window.open('https://ad2001.gitbook.io/a-noobs-guide-to-arm-exploitation')
              }
            />
            <BlogCard
              title='Android Security::Exported Broadcast Receiver'
              authors={[{ name: 'Ajin Deepak', avatar: '/images/authors/ad-profile.webp' }]}
              publishedDate={new Date('2024-03-31')}
              description={`This article provides an in-depth examination of exported broadcast receivers in Android, showcasing their functionality, potential vulnerabilities, and methods of exploitation. Through illustrative examples, such as creating, identifying, and testing exported receivers, it highlights the risks of insecure implementation, including command injection. The hands-on approach includes crafting exploit scenarios, testing with ADB, and achieving code execution. This tutorial is ideal for developers and security enthusiasts aiming to enhance their understanding of Android security and identify risks associated with exported broadcast receivers.`}
              onReadMore={() => navigate('/blogs/android-security-exported-broadcast-reciever')}
            />
            <BlogCard
              title='Android CTF Juicy Bar::Bruteforce'
              authors={[{ name: 'Ajin Deepak', avatar: '/images/authors/ad-profile.webp' }]}
              publishedDate={new Date('2024-04-21')}
              description={`Dive into the exciting world of Android CTF challenges with this detailed walkthrough of the Juicy Bar brute force level. In this post, Ajin Deepak guides you through identifying the validation method, crafting a Frida script, and brute-forcing a 4-digit PIN to uncover the flag. Whether you're a beginner or a seasoned reverse engineer, you'll find actionable insights, helpful tools, and links to deepen your Android security knowledge.`}
              onReadMore={() => navigate('/blogs/juicy-bar-bruteforce')}
            />
            <BlogCard
              title='Android CTF Juicy Bar::Meet Frida'
              authors={[{ name: 'Ajin Deepak', avatar: '/images/authors/ad-profile.webp' }]}
              publishedDate={new Date('2024-04-07')}
              description={`A detailed write-up of the Frida challenge from the Android CTF "Juicy Bar," showcasing reverse engineering techniques using Frida to extract three flags. The post walks through analyzing the APK, understanding decompiled Java code, and crafting custom Frida scripts to hook methods and manipulate application logic.`}
              onReadMore={() => navigate('/blogs/juicy-bar-meet-frida')}
            />
          </div>
        </div>
        <div />
      </div>
    </div>
  );
}

export default BlogList;
