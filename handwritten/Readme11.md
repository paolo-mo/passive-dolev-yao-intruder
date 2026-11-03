# Hand-Written Extraction Experiments

Three minimal two-agent Java programs that exercise the PCAP-to-object
extraction pipeline on a single host. Together they support the claim
that the extraction stage of the reconstruction pipeline is independent
of the `anbx` compiler and of the `anbxj` runtime library.

## What the experiments validate

| Property | `Tutorial_06` | `Tutorial_07` | `Hybrid RSA+AES` |
|----------|---------------|---------------|------------------|
| Implementation not produced by the `anbx` compiler | yes | yes | yes |
| No `anbxj` jar on the classpath at compile or run time | no | yes | yes |
| Crypto-wrapped objects on the wire | `Crypto_SignedObject` (step 4) | `SealedObject` (step 3), `SignedObject` (step 4) | `PublicKey` (step 1), `byte[]` (steps 2–4) |
| Directional streams recovered from a single-IP capture | yes | yes | yes |
| Multi-object streams distributed into per-step files | yes | yes | yes |

`Tutorial_06` shows that object recovery does not require the
implementation to have been produced by the `anbx` compiler.
`Tutorial_07` goes further and removes the runtime dependency: it uses
only the standard JDK, and its extractor imports only `java.io` and
`java.util`. 

The hybrid experiment (adapted from
https://github.com/mark4865/JavaCryptoClientServer) probes a third
wire-format path: an interface-typed public key, which the JDK
deserialises as its internal concrete class
`sun.security.rsa.RSAPublicKeyImpl`, and raw `byte[]` arrays. It also
uses a different cryptographic construction (RSA key transport,
AES-GCM, detached RSA signature) from the symmetric constructions of
the two tutorials.

## What the experiments do not validate

Stages 1 and 2 of the pipeline (JavaDocker generation and Docker
execution) do not apply: the programs were run directly and captured on
the loopback interface. Stage 4 (session build, connection pairing,
candidate enumeration) is trivial: each experiment produces a single
connection with `K = 1` and `N = 1`. Within Stage 5, the
compiler-generated `ObjCheck` class and the candidate-scoring loop of
Pass A, and the compiler invocation and intruder role of Pass B, were
not exercised. The passive intruder role was not generated or executed,
because the hand-written programs have no `anbx` specification from
which its checks are derived. The recovered objects were therefore not
validated against a type system, equality constraints, or freshness
requirements. A hand-written implementation can be reconstructed
without a formal model, given a channel-to-step map; validating the
reconstruction still requires one.

---

## Prerequisites

- JDK 21 (with `javac` and `java` on `PATH`)
- `AnBxJ.jar` and the `keystore/` directory (needed for `Tutorial_06` only)
- Python 3.14, TShark, and the `anbx` extraction scripts
  (`jpcap2ser.py`, `outparse.py`, `jpcap2ser.cfg`)
- Wireshark with Npcap **loopback support enabled**, run as Administrator

On Windows, Npcap's loopback adapter is not installed by default.
Reinstall Npcap and tick "Support loopback traffic" during setup.
Without it, Wireshark cannot see `127.0.0.1` traffic.

---

## Files

| File | Purpose |
|------|---------|
| `Tutorial_06.java` | Uses `anbxj`. Server / client program. |
| `Tutorial_06.properties` | Crypto config read by the running program (not by the extraction stage) |
| `Tutorial_06_Steps.java` | Enum `STEP_1` ... `STEP_5` |
| `Tutorial_06_Channels.java` | Enum `CLIENT_to_SERVER`, `SERVER_to_CLIENT` |
| `Tutorial_06_ObjCheck_Map.java` | Hand-written channel-to-step map |
| `Tutorial_07.java` | Uses only the standard JDK. Server / client program and `Message` class in one file. |
| `Server.java`, `Client.java` | Hybrid RSA+AES program. Uses only the standard JDK. |
| `ExtractCheck_06.java` | Reads directional `.ser` files, writes per-step files. Used for `Tutorial_06`. |
| `ExtractCheck_07.java` | Same as `ExtractCheck_06.java` but with the `CHANNELS` map pre-set for `Tutorial_07`. |
| `ExtractCheck_hybrid.java` | Same, but with the `CHANNELS` map pre-set for the hybrid experiment. |

---

## Compile

For `Tutorial_06`:

javac -cp AnBxJ.jar Tutorial_06_Steps.java Tutorial_06_Channels.java ^
Tutorial_06.java Tutorial_06_ObjCheck_Map.java
javac -cp .;AnBxJ.jar ExtractCheck_06.java

For `Tutorial_07`:

javac Tutorial_07.java ExtractCheck_07.java

For the hybrid:

javac Server.java Client.java
javac ExtractCheck_hybrid.java

The last two commands compile with no jar on the classpath. That is the
point of the experiments.

## Check the channel-to-step map

java -cp .;AnBxJ.jar Tutorial_06_ObjCheck_Map

Expected:

SERVER_to_CLIENT -> [STEP_1, STEP_3, STEP_5]
CLIENT_to_SERVER -> [STEP_2, STEP_4]

For `Tutorial_07` and the hybrid, the corresponding maps are inside
`ExtractCheck_07.java` and `ExtractCheck_hybrid.java`.

---

## Capture

`Tutorial_06` uses port **6669**. Do not use 6667: Wireshark's IRC
dissector claims that port and leaves the `data` field empty.

`Tutorial_07` uses port **6671**, which is not claimed by any dissector.

The hybrid uses port **9001**.

In Wireshark, select the loopback adapter and start the capture. Run
the server in one prompt and the client in another:

:: Tutorial_06
java -cp .;AnBxJ.jar Tutorial_06 server
java -cp .;AnBxJ.jar Tutorial_06 client

:: Tutorial_07
java Tutorial_07 server
java Tutorial_07 client

:: Hybrid
java Server
java Client

Interact:

**Tutorial_06.** The server asks for a name (type `alice`). The server
sends a challenge; paste the whole line back and press Enter. The
server confirms the signature.

**Tutorial_07.** The server sends a greeting; the client sends a name.
The server sends a sealed message; the client sends a signed message.
The server confirms receipt.

**Hybrid.** The server asks for a message. The client receives the
public key, sends the wrapped AES key, receives the encrypted message
and signature, and prints the decrypted message and the signature
validation result.

Stop the capture. Filter `tcp.port == 6669` (or `6671`, or `9001`);
the protocol column must read **TCP**, not IRC. Save as
`Tutorial_06.pcap` (or `Tutorial_07.pcap`, or
`handwritten_hybrid_rsa_aes.pcap`).

---

## Extract streams

python <path>\jpcap2ser.py Tutorial_06 --pcap Tutorial_06.pcap --allstreams --emit-meta
python <path>\jpcap2ser.py Tutorial_07 --pcap Tutorial_07.pcap --allstreams --emit-meta
python <path>\jpcap2ser.py handwritten_hybrid_rsa_aes --pcap handwritten_hybrid_rsa_aes.pcap --allstreams --emit-meta

Expected for each protocol: two protocol streams (one per direction),
plus any unrelated background traffic on the loopback interface. The
hybrid capture, for example, produced four streams: two protocol
streams on ports 6669 and 24011, and two background streams on ports
2489–2492 that were ignored because they are not in the `CHANNELS`
map.

Confirm via the `streams.json` file: the record whose `src_port` is
the server port (6669, 6671, or 9001) is the server-to-client stream.

Note that `outparse.py` requires the direction-key guard described in
the paper's Section 3.2: when both endpoints share an IP, the grouping
key `(tcp.stream, src_ip, dst_ip)` collapses the two directions, and
the guard adds `src_port` to disambiguate them. The guard is inert for
Docker captures, where the two endpoints always have distinct IPs.

---

## Extract objects

Set the `CHANNELS` map in `ExtractCheck_06.java` (or
`ExtractCheck_07.java`, or `ExtractCheck_hybrid.java`) to match the
filenames produced by `outparse.py`.

For `Tutorial_06`:

private static final Map<String, List<String>> CHANNELS = Map.of(
    "Tutorial_06_STREAM_2_1.ser", List.of("STEP_2", "STEP_4"),
    "Tutorial_06_STREAM_2_2.ser", List.of("STEP_1", "STEP_3", "STEP_5")
);

For `Tutorial_07`:

private static final Map<String, List<String>> CHANNELS = Map.of(
    "Tutorial_07_STREAM_1_1.ser", List.of("STEP_1", "STEP_3", "STEP_5"),
    "Tutorial_07_STREAM_1_2.ser", List.of("STEP_2", "STEP_4")
);

For the hybrid:

private static final Map<String, List<String>> CHANNELS = Map.of(
    "handwritten_hybrid_rsa_aes_STREAM_3_2.ser", List.of("STEP_2"),
    "handwritten_hybrid_rsa_aes_STREAM_3_1.ser", List.of("STEP_1", "STEP_3", "STEP_4")
);

Run:

java -cp .;AnBxJ.jar ExtractCheck_06 Tutorial_06
java ExtractCheck_07 Tutorial_07
java ExtractCheck_hybrid handwritten_hybrid_rsa_aes

Expected for Tutorial_06:

Tutorial_06_STREAM_2_2.ser -> Tutorial_06_1_STEP_1.ser  (java.lang.String)
Tutorial_06_STREAM_2_2.ser -> Tutorial_06_1_STEP_3.ser  (java.lang.String)
Tutorial_06_STREAM_2_2.ser -> Tutorial_06_1_STEP_5.ser  (java.lang.String)
Tutorial_06_STREAM_2_1.ser -> Tutorial_06_1_STEP_2.ser  (java.lang.String)
Tutorial_06_STREAM_2_1.ser -> Tutorial_06_1_STEP_4.ser  (anbxj.Crypto_SignedObject)

Expected for Tutorial_07:

Tutorial_07_STREAM_1_1.ser -> Tutorial_07_1_STEP_1.ser  (java.lang.String)
Tutorial_07_STREAM_1_1.ser -> Tutorial_07_1_STEP_3.ser  (javax.crypto.SealedObject)
Tutorial_07_STREAM_1_1.ser -> Tutorial_07_1_STEP_5.ser  (java.lang.String)
Tutorial_07_STREAM_1_2.ser -> Tutorial_07_1_STEP_2.ser  (java.lang.String)
Tutorial_07_STREAM_1_2.ser -> Tutorial_07_1_STEP_4.ser  (java.security.SignedObject)

Expected for the hybrid:

handwritten_hybrid_rsa_aes_STREAM_3_1.ser -> handwritten_hybrid_rsa_aes_1_STEP_1.ser  (sun.security.rsa.RSAPublicKeyImpl)
handwritten_hybrid_rsa_aes_STREAM_3_1.ser -> handwritten_hybrid_rsa_aes_1_STEP_3.ser  ([B)
handwritten_hybrid_rsa_aes_STREAM_3_1.ser -> handwritten_hybrid_rsa_aes_1_STEP_4.ser  ([B)
handwritten_hybrid_rsa_aes_STREAM_3_2.ser -> handwritten_hybrid_rsa_aes_1_STEP_2.ser  ([B)

The three experiments recover five, five, and four objects
respectively. The reported classes matched the sent classes on every
step, including the two crypto wrappers in `Tutorial_07`, the `anbxj`
crypto wrapper in `Tutorial_06`, and the interface-typed public key and
raw `byte[]` arrays in the hybrid.