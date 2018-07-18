#  Build

1) Check out the go code:

    $go get github.com/OperatorFoundation/Shapeshifter-obfs4-OpenVPN-Transport-Plugin-Cgo

2) From the go project directory run the following command to generate the library files that you will need:

    $go build -buildmode=c-shared -o Shapeshifter-obfs4-OpenVPN-Transport-Plugin.so

3) Copy the following files into the Xcode/C project directory: Shapeshifter-obfs4-OpenVPN-Transport-Plugin.h and Shapeshifter-obfs4-OpenVPN-Transport-Plugin.so

4) In Xcode go to Edit Scheme -> Options. For "Working Directory" choose to "Use Custom Working Directory" and then select the main Xcode/C project directory. This will make sure that the Xcode project knows how to find our GO library.

5) Build the current scheme.
