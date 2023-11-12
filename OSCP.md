# OSCP (Offensive Security Certified Professional) Writeup

![OSCP Logo](https://www.vumetric.com/wp-content/uploads/OSCP-certification-logo.png)

This repository contains my writeup and documentation for successfully completing the Offensive Security Certified Professional (OSCP) certification. The OSCP certification is a challenging and highly regarded certification for professionals in the field of ethical hacking and penetration testing.

## Table of Contents

- [Me](#Me)
- [About OSCP](#about-oscp)
- [Exam Overview](#exam-overview)
- [Preparation](#preparation)
- [Lab Environment](#lab-environment)
- [Exam Experience](#exam-experience)
- [Useful Resources](#useful-resources)
- [Disclaimer](#disclaimer)

## Me
To provide some background on how I embarked on the OSCP journey, I first learned about this certification in April 2020 during the COVID-19 pandemic. My mentor introduced me to the OSCP, describing it as one of the most practical and challenging exams, lasting a grueling 24 hours. At the time, my technical expertise was limited to basic Linux, Python, Java, and some networking skills.

This was my second year in college, pursuing a Bachelor of Science in Information Technology with a specialization in network security. Despite taking a few courses, nothing had truly captured my interest like the OSCP did. I remember thinking, "How could I ever conquer such a demanding exam? It's a marathon at 24 hours, requires months of preparation, and, as a college student, the cost was substantial."

My mentor's advice was to start by tackling Hack The Box (HTB) and immerse myself in the world of cybersecurity by watching the incredible ippsec's videos. And so, that's exactly what I did! The experience was transformative. I vividly recall rooting "Bashed," an easy Linux machine that, at the time, felt overwhelmingly complex. I embarked on a journey through TJnull's OSCP-like HTB list and completed around 30 different boxes.

What made this period particularly unique was that I had the luxury of being in quarantine, enabling me to fully dedicate myself to learning. Admittedly, I leaned heavily on write-ups and ippsec's guidance to navigate some challenges and avoid rabbit holes. Nevertheless, I felt an immense sense of accomplishment and acquired practical skills that I could discuss during interviews and apply to my academic studies.

The following semester, I enrolled in an ethical hacking class and excelled. My prior practice with HTB gave me a significant advantage, as many students had never ventured into network scanning or obtained a reverse shell. I realized that I had acquired invaluable skills for my future career. This practical knowledge paved the way for my first security internship.

In my junior year of college, an insurance company posted a security analyst co-op position. Eager to secure my entry into the field, I applied. During the interview, one of the questions revolved around Active Directory, and I confidently shared my experience with Kerberoasting, which resonated positively with the interviewers. Approximately three weeks later, I received the official offer and commenced my role in January 2021.

This marked a significant milestone in my journey. I felt a profound sense of gratitude towards the company for being exceptional mentors and providing me with this opportunity. I spent nearly two years as an intern at this company, transitioning under two different managers who played an instrumental role in my growth, alongside my supportive colleagues.

With this wealth of experience, I pursued certifications in the form of Security+ and CCNA, further cementing my knowledge of fundamental security concepts and networking. These certifications were not only valuable but also cost-effective.

In my senior year of college, I received an offer to join an IT rotational program at a Forbes top 20 company—an opportunity I wholeheartedly embraced. I had the privilege to select my role and ended up in a cybersecurity research engineering position. This new role excited me as it promised to unveil a different facet of security and expand my knowledge.

In this current position, I primarily focus on API security, delving into the realm of web application attacks involving APIs. Prior to this role, APIs were a foreign concept to me, and I had limited knowledge of their functionality. However, my OSCP journey, undertaken during this period, significantly contributed to my understanding of ethical hacking and the hacker's perspective. This newfound perspective greatly enhances my ability to explain security concepts from a hacker's viewpoint.

And so, my OSCP journey concludes with my successful achievement of the certification on June 2nd, 2023, while I continued my full-time job in the realm of API security.

## About OSCP

The Offensive Security Certified Professional (OSCP) certification is one of the most well-recognized certifications for penetration testers and ethical hackers. It is offered by Offensive Security and is known for its rigorous hands-on exam.

## Exam Overview

The OSCP exam consists of a 24-hour practical test in which you are required to exploit a series of machines to obtain flags. The exam also includes a report-writing portion, where you must document your findings and the exploitation process.

## Preparation

In preparation for the OSCP exam, I:

- Completed the [PWK Course](https://www.offensive-security.com/pwk-oscp/) offered by Offensive Security.
- Practiced extensively in the lab environment.
- Practice 30+ labs in PWK 2022
- Practice 30+ labs in PWK 2023
- Completed OSCP A, B and C practice exams
- Completed Relia and Medtech
- Exploited various methods of AD attacks in OSCP A,B and C reptiavetley (Try everything taught in pwk 2023)
- Proving Practice TJ Nulls List

## Lab Environment

Throughout my OSCP journey, I had the invaluable OSCP Learn One package, which proved to be a lifesaver while balancing a full-time job and personal life. I wholeheartedly recommend investing in the L1 package because it affords you flexibility concerning your mental, emotional, and physical well-being. I dedicated approximately four hours every day, sometimes extending to 5+ hours on Saturdays and Sundays. The L1 package provided ample time to work through all the PDFs, exercises, and most of the lab environment.

An interesting note is that I initially purchased the PWK 2022 course, but about two months later, the PWK 2023 material was released. In hindsight, this fortuitous timing turned out to be a blessing. The PWK 2022 labs presented quite a challenge due to their outdated nature and the shared lab environment. Many times, I found myself on the brink of rooting a machine, only to have it reverted by another student. I wasted a fair amount of time simply figuring out how to navigate the shared environment. The 2023 lab environment, on the other hand, was exceptional. I found that if you successfully tackled Relia, Skylark, and OSCP ABC, you were exceptionally well-prepared for the exam. Despite the initial inconvenience, I was genuinely pleased with the updated material, which felt contemporary and directly relevant to the exam.

As a piece of advice, I strongly recommend joining an OSCP study group or engaging with the Offsec Discord community. However, after working through over 60 labs, I reached a point of saturation with machine after machine. To break away from this routine, I transitioned to Proving Grounds. This shift provided a refreshing change, allowing me to disconnect from Discord and simply hack. Engaging in Proving Grounds practice is a crucial aspect of your lab experience. Try to root approximately 10 Windows and 10 Linux machines to expand your knowledge.

To be candid, I sought assistance on most of the medium and hard boxes offered by Offsec. While I was confident in the skills I had learned, I remained humbled by the constant stream of new knowledge presented by these challenges. At some point, you come to realize that you can't possibly know everything. The "Try Harder" approach is designed to teach you how to research and learn independently. This, I believe, is the most significant takeaway – the ability to be resourceful, find information on your own, and apply it in real-time scenarios.

Lastly, please heed my advice and complete the recommended labs. They are pivotal to your OSCP exam experience. In particular, for Active Directory (AD), review the PWK material and repeat the OSCP ABC AD sections multiple times. Immerse yourself in it, take extensive notes on every facet of hacking into AD, and develop a deep understanding of how it operates.

## Exam Experience

I took the OSCP exam on [June 2nd, 2023]. Here are some key points about my experience:

In preparation for my OSCP exam, I initially scheduled it for the third week of June. However, as I progressed through my OSCP training, I realized that waiting that long wasn't optimal. After all, I had already conquered over 60 lab machines, combining my efforts from PWK 2022 and PWK 2023. The anticipation became overwhelming, and I made the decision to reschedule my exam for the first week of June. This adjustment helped me reach my goal much sooner.

To ensure I was at my sharpest, I chose to start the exam at noon, a time when I'm most alert. I figured that even if I couldn't sleep due to exam nerves the night before, starting with a well-rested morning would counteract any potential grogginess. I've always been known to stay awake when I'm excited about something, but thankfully, the night before the exam, I managed to get to bed around 10:30 or 11:00 pm. To take my mind off the impending challenge, I deliberately distracted myself by watching light-hearted shows that required minimal brainpower. This approach helped me relax and contributed to my success on exam day.

I woke up around 9 am, feeling remarkably refreshed. While I was certainly tired, I had allotted three hours for a healthy breakfast, ample hydration, and a leisurely outdoor walk. I had purchased two energy drinks the night before and consumed the first one during my slow morning walk. I wanted to avoid the jitters and subsequent energy crash, so I took my time, sipping the energy drink over the course of 1.5 hours. This brought me to the start of my exam at 12 pm.

However, I encountered some technical network issues that delayed the beginning of my exam until 1 pm. It was disappointing to lose an hour, but I pressed on. I began by running automated scans on the three independent machines and documented the results in Cherry for later reference after the Active Directory section.

Moving on to the Active Directory portion, I was elated to root it in under an hour. I took meticulous notes and captured screenshots of every step and flag used to compromise the Domain Controller. At this point, I had earned a substantial 40 points and an additional 10 bonus points for completing 80% of each exercise in the PWK 2022 course.

With just one more box or a combination of footholds on two boxes needed, I set my sights on the next target. Although I secured a foothold on the box, I spent roughly three hours struggling with privilege escalation. No matter how much I Googled and employed WinPEAS, I couldn't find the breakthrough I needed. Frustration mounted, and I decided to take a break, venturing outside. I can't emphasize enough how crucial these breaks are. Whenever you make progress or collect some points, stepping outside to touch base with nature or breathe in fresh air helps clear your mind.

Sitting at around 60 potential points, I needed just one more foothold or privilege escalation to pass. I revisited the output for the two remaining boxes in Cherry and Tree but found no foothold. After a few more hours of frustration, annoyance, and fluctuating emotions, I hit a wall. The sun had set, and I was stumped. This is where many OSCP candidates falter, as evident in the OSCP subreddit. I felt like I might become one of those stories.

It's a unique moment because you're tantalizingly close to success, yet you know you must embody the OSCP motto, "Try Harder." I decided to take another walk and reviewed my Cherry Tree notes from the two standalone machines. I stumbled upon something I hadn't considered before, and it led to a fascinating discovery. Following this lead, I eventually secured a foothold on another standalone machine. Success! The "Try Harder" motto had paid off, and I was ecstatic.

I took another break to unwind before attempting privilege escalation on this machine. I could have stopped here, but it was around midnight, and I was anxious that my bonus points might not count for some unforeseen reason. So, I decided to push forward. I managed to root the machine six hours later, around 4 am. At this point, I was incredibly wired, and my two consumed energy drinks kept me wide awake.

With 80 points in the bag, I felt considerably more confident about passing. I took a four-hour nap, woke up at 8 am, and tried to squeeze in more points, but no further progress was made. Exhausted and having captured all necessary screenshots, I decided to end my exam about 30 minutes early and commenced working on my report. Interestingly, my power went out two hours later, and I couldn't work on the report for another 12 hours. I felt fortunate that this mishap didn't occur during the exam.

After painstakingly compiling 60 pages of documentation and numerous screenshots, I finally completed my report and submitted it. Two business days later, I received the email confirming my passing grade—followed, of course, by a celebratory LinkedIn post!

## Useful Resources

- [OSCP Sub-Reddit](https://www.reddit.com/r/oscp/)
- [TJ Nulls OSCP Prep](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit?usp=sharing)
- [Proving Grounds](https://www.offsec.com/labs/)
## Disclaimer

This repository is for educational and informational purposes only. The OSCP exam is a certification offered by Offensive Security, and all rights, content, and materials related to the OSCP certification are owned by Offensive Security.

The writeup in this repository is based on my personal experiences and does not disclose or compromise any sensitive information or proprietary material. Please use this repository as a reference and guide to your own OSCP journey.

---

Developed by [xsudoxx](https://github.com/xsudoxx)
