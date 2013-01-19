##Introduction

CommSec provides encryption over datagram-style communications with goals of
confidentiallity, integrity, and replay protection. The original motivation was
to provide a thread-safe alternative to a subset of the functionallity of the
secure-sockets package.

##Use

Use wisely.  If you aren't familiar with the concept of ephemeral keys then use
secure-sockets instead. There has been no peer review and no formal development
methodology was used, so users with strong security needs are advised to weigh
the risks.

##Types
* Contexts: Contexts can either be 'In', for decrypting/receiving, or 'Out',
  for encrypting/sending.  A context includes an AES key and counter.

* Connection: a bidirectional communication channel that allows
  sending/receiving.  Connections can be 'Unsafe', meaning they shouldn't be
  used concurrently, or 'Safe', meaning they protect critical access with an MVar
  and should be safe for concurrent use.  Notice the constructor to connection is
  exported, allowing users or third-party packages to use the commsec calls with
  any sort of 'Socket'.

##Operations

* encode/decode - Using an 'InContext', encode will package up a plaintext
  message into a ciphertext datagram.  Decode will unpack these datagrams into
  plaintext messages.

* connect/accept - Connect and Accept are bundled up socket operations that
  return a 'Connection' which can be used for bidirectional communication.

* send/recv - Send or receive data over a previously established connection

##Exceptions

The type 'CommSecError' is often returned via an 'Either' type when working at
the level of Network.CommSec.Package.  For encoding, the only time an error can
occur is at the end of life of an OutContext and an exception is used.  When
receiving (Network.Commsec.recv) the operation retries on most errors (Duplicate
message, invalid ICV, etc) unless it is an 'OldContext' error, which is thrown
as an exception.  Sending message (Network.CommSec.send) can also throw 'OldContext'.

##TODO

 * Make a commsec-pki or commsec-sshkey package that performs authentication, key agreement, and maybe exception handling/rekey.

##Performance

Currently the performance of comm-sec is all about the AESgcm routine, which is sub-optimal.  This is expected to be improved.

<table>
<tr>
<td>Operation</td>         <td>Size (B)</td>     <td>Time (us)</td>
</tr>
<tr>
<td>Send(safe)</td>        <td>16</td>           <td>2</td>
</tr>
<tr>
<td>Send(safe)</td>        <td>2048</td>         <td>38</td>
</tr>
<tr>
<td>Send+Recv(safe)</td>   <td>16</td>         <td>10</td>
</tr>
<tr>
<td>Send+Recv(safe)</td>   <td>2048</td>         <td>76</td>
</tr>
<tr>
<td>secure-sockets package</td> <td>16</td>         <td>29</td>
</tr>
<tr>
<td>secure-sockets package</td> <td>2048</td>         <td>40</td>
</tr>
</table>

##Related Tools
To obtain ephemeral keys you might want to use your systems IKE
daemon, a diffe-helman computation with authentication, or perhaps an
MQV using Haskell's hecc package.

##DISCLAIMER
This package is intended as an extremely light-weight communications
security solution.  The current goal is to be "morally correct", that
is - performing all the right operations but admittedly without
sufficient formallity or peer-review for a high level of trust.

In short: use at your own risk.
