##
* send/recv - Send or receive data over a previously established connection

##Exceptions

The type 'CommSecError' is often returned via an 'Either' type when working at
the level of Network.CommSec.Package.  For encoding, the only time an error can
occur is at the end of life of an OutContext and an exception is used.  When
receiving (Network.Commsec.recv) the operation retries on most errors (Duplicate
message, invalid ICV, etc) unless it is an 'OldContext' error, which is thrown
as an exception.  Sending message (Network.CommSec.send) can also throw 'OldContext'.

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
<td>Send+Recv(safe)</td>   <td>16</td>         <td>6</td>
</tr>
<tr>
<td>Send+Recv(safe)</td>   <td>2048</td>         <td>69</td>
</tr>
<tr>
<td>
</table>

##Related Tools
To obtain ephemeral keys you might want to use your systems IKE
daemon, a diffe-helman computation with authentication, or perhaps an
MQV using Haskell's hecc package.

Alternatively, you can use [commsec-keyexchange](https://github.com/TomMD/commsec-keyexchange).

##DISCLAIMER
This package is intended as an extremely light-weight communications
security solution.  The current goal is to be "morally correct", that
is - performing all the right operations but admittedly without
sufficient formallity or peer-review for a high level of trust.

In short: use at your own risk.
