# Cryptographic Libraries
*An Empirical Study of Vulnerabilities in Cryptographic Libraries

The security of the Internet rests on a small number of open-source cryptographic libraries: A vulnerability in any one of them threatens to compromise a significant percentage of web traffic. Despite this potential for security impact, the characteristics and causes of vulnerabilities in cryptographic software are not well understood. In this work, we conduct the first comprehensive, longitudinal analysis of cryptographic libraries and the vulnerabilities they produce. We collect data from the National Vulnerability Database, individual project repositories and mailing lists, and other relevant sources for all widely used cryptographic libraries.

In our investigation of the causes of these vulnerabilities, we find evidence of a correlation between the complexity of these libraries and their (in)security, empirically demonstrating the potential risks of bloated cryptographic codebases. Among our most interesting findings is that only 29.8% of vulnerabilities in cryptographic libraries are cryptographic issues while 37.4% of vulnerabilities are memory safety issues, indicating that systems-level bugs are a greater security concern than the actual cryptographic procedures. We further compare our findings with non-cryptographic systems, observing that cryptographic libraries, particularly those written in C/C++, are up to three times as complex as similar non-cryptographic systems, and that this excess complexity appears to produce vulnerabilities at higher rates in cryptographic libraries than in non-cryptographic software.

Additional information can be found in the related paper.
