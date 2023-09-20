# HeX

HeX is a dynamic searchable symmetric encryption (DSSE) scheme based on Intel SGX. It can achieve forward search privacy and backward privacy stronger than Type-I. It can also support Boolean queries and range queries with high efficiency.

HeX-basic is for the single keyword-file search and HeX-range is for range queries. Maiden is from [1] and SE_SGX_2 is from [2]. All implementations are completed based on https://github.com/MonashCybersecurityLab/SGXSSE.

The datasets for HeX-basic include a synthetic dataset (SD) and a portion of Enron e-mail dataset. The 'count-1w.csv' to generate SD can be downloaded from https://norvig.com/ngrams/. The 'maildir' folder for Enron dataset can be downloaded from https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz and ungzipped.


# HeX-basic

1. Install Intel SGX Driver, SDK and PSW for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode and Debug build:
   
       `` $ cd HeX-basic && make clean``
       
       `` $ make SGX_MODE=HW SGX_DEBUG=1``

3. Execute the binary directly:
  `
    $ ./cryptoTestingApp
  `

4. This version is tested on Ubuntu Server 18.04 LTS 64-bit OS with SGX >=2.0


# HeX-range

1. Install Intel SGX Driver, SDK and PSW for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode and Debug build:
   
       `` $ cd HeX-range && make clean``
       
       `` $ make SGX_MODE=HW SGX_DEBUG=1``

3. Execute the binary directly:
  `
    $ ./cryptoTestingApp
  `

4. This version is tested on Ubuntu Server 18.04 LTS 64-bit OS with SGX >=2.0


# Maiden

1. Install Intel SGX Driver, SDK and PSW for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode and Debug build:
   
       `` $ cd Maiden && make clean``
       
       `` $ make SGX_MODE=HW SGX_DEBUG=1``

3. Execute the binary directly:
  `
    $ ./cryptoTestingApp
  `

4. This version is tested on Ubuntu Server 18.04 LTS 64-bit OS with SGX >=2.0


# SE_SGX_2

1. Install Intel SGX Driver, SDK and PSW for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode and Debug build:
   
       `` $ cd SE_SGX_2 && make clean``
       
       `` $ make SGX_MODE=HW SGX_DEBUG=1``

3. Execute the binary directly:
  `
    $ ./cryptoTestingApp
  `

4. This version is tested on Ubuntu Server 18.04 LTS 64-bit OS with SGX >=2.0


# Reference
[1] Vo V, Lai S, Yuan X, et al. Towards efficient and strong backward private searchable encryption with secure enclaves[C]//International Conference on Applied Cryptography and Network Security. Cham: Springer International Publishing, 2021: 50-75.

[2] Vo V, Lai S, Yuan X, et al. Accelerating forward and backward private searchable encryption using trusted execution[C]//Applied Cryptography and Network Security: 18th International Conference, ACNS 2020, Rome, Italy, October 19–22, 2020, Proceedings, Part II 18. Springer International Publishing, 2020: 83-103.