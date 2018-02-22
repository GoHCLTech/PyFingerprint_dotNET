using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.IO.Ports;
using System.Linq;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PyFingerprint_dotNET
{
    public class PyFingerprintScanner :IDisposable
    {
        #region "Constants"
        //Baotou start byte
        private const Int32 FINGERPRINT_STARTCODE = 0xEF01;

        // Packet identification
        private const byte FINGERPRINT_COMMANDPACKET = 0x01;

        private const byte FINGERPRINT_ACKPACKET = 0x07;
        private const byte FINGERPRINT_DATAPACKET = 0x02;
        private const byte FINGERPRINT_ENDDATAPACKET = 0x08;

        // Instruction codes
        private const byte FINGERPRINT_VERIFYPASSWORD = 0x13;
        private const byte FINGERPRINT_SETPASSWORD = 0x12;
        private const byte FINGERPRINT_SETADDRESS = 0x15;
        private const byte FINGERPRINT_SETSYSTEMPARAMETER = 0x0E;
        private const byte FINGERPRINT_GETSYSTEMPARAMETERS = 0x0F;
        private const byte FINGERPRINT_TEMPLATEINDEX = 0x1F;
        private const byte FINGERPRINT_TEMPLATECOUNT = 0x1D;

        private const byte FINGERPRINT_READIMAGE = 0x01;

        // Note: The documentation mean upload to host computer.
        private const byte FINGERPRINT_DOWNLOADIMAGE = 0x0A;

        private const byte FINGERPRINT_CONVERTIMAGE = 0x02;

        private const byte FINGERPRINT_CREATETEMPLATE = 0x05;
        private const byte FINGERPRINT_STORETEMPLATE = 0x06;
        private const byte FINGERPRINT_SEARCHTEMPLATE = 0x04;
        private const byte FINGERPRINT_LOADTEMPLATE = 0x07;
        private const byte FINGERPRINT_DELETETEMPLATE = 0x0C;

        private const byte FINGERPRINT_CLEARDATABASE = 0x0D;
        private const byte FINGERPRINT_GENERATERANDOMNUMBER = 0x14;
        private const byte FINGERPRINT_COMPARECHARACTERISTICS = 0x03;

        // Note: The documentation mean download from host computer.
        private const byte FINGERPRINT_UPLOADCHARACTERISTICS = 0x09;

        // Note: The documentation mean upload to host computer.
        private const byte FINGERPRINT_DOWNLOADCHARACTERISTICS = 0x08;

        // Packet reply confirmations
        private const byte FINGERPRINT_OK = 0x00;
        private const byte FINGERPRINT_ERROR_COMMUNICATION = 0x01;

        private const byte FINGERPRINT_ERROR_WRONGPASSWORD = 0x13;

        private const byte FINGERPRINT_ERROR_INVALIDREGISTER = 0x1A;

        private const byte FINGERPRINT_ERROR_NOFINGER = 0x02;
        private const byte FINGERPRINT_ERROR_READIMAGE = 0x03;

        private const byte FINGERPRINT_ERROR_MESSYIMAGE = 0x06;
        private const byte FINGERPRINT_ERROR_FEWFEATUREPOINTS = 0x07;
        private const byte FINGERPRINT_ERROR_INVALIDIMAGE = 0x15;

        private const byte FINGERPRINT_ERROR_CHARACTERISTICSMISMATCH = 0x0A;

        private const byte FINGERPRINT_ERROR_INVALIDPOSITION = 0x0B;
        private const byte FINGERPRINT_ERROR_FLASH = 0x18;

        private const byte FINGERPRINT_ERROR_NOTEMPLATEFOUND = 0x09;

        private const byte FINGERPRINT_ERROR_LOADTEMPLATE = 0x0C;

        private const byte FINGERPRINT_ERROR_DELETETEMPLATE = 0x10;

        private const byte FINGERPRINT_ERROR_CLEARDATABASE = 0x11;

        private const byte FINGERPRINT_ERROR_NOTMATCHING = 0x08;

        private const byte FINGERPRINT_ERROR_DOWNLOADIMAGE = 0x0F;
        private const byte FINGERPRINT_ERROR_DOWNLOADCHARACTERISTICS = 0x0D;

        // Unknown error codes
        private const byte FINGERPRINT_ADDRCODE = 0x20;
        private const byte FINGERPRINT_PASSVERIFY = 0x21;

        private const byte FINGERPRINT_PACKETRESPONSEFAIL = 0x0E;

        private const byte FINGERPRINT_ERROR_TIMEOUT = 0xFF;
        private const byte FINGERPRINT_ERROR_BADPACKET = 0xFE;
        #endregion;

        //@attribute integer(4 bytes) __address
        //Address to connect to sensor.

        //@attribute integer(4 bytes) __password
        //Password to connect to sensor.

        //@attribute Serial __serial
        //UART serial connection via PySerial.

        uint __address;
        uint __password;
        SerialPort __serial;

        public PyFingerprintScanner(string port = "COM3", int baudRate = 57600, uint address = 0xFFFFFFFF, uint password = 0x00000000)
        {
            if (!SerialPort.GetPortNames().Contains(port))
            {
               throw new Exception("The fingerprint sensor port " + port + " was not found!");
            }

            if (baudRate < 9600 || baudRate > 115200 || baudRate % 9600 != 0)
            {
                throw new Exception("The given baudrate is invalid!");
            }

            if (address < 0x00000000 || address > 0xFFFFFFFF)
            {
                throw new Exception("The given address is invalid!");
            }

            if (password < 0x00000000 || password > 0xFFFFFFFF)
            {
                throw new Exception("The given password is invalid!");
            }

            __address = address;
            __password = password;

            __serial = new SerialPort(port, baudRate, Parity.None, 8, StopBits.One);
            __serial.ReadTimeout = 2000;

            if (__serial.IsOpen)
            {
                __serial.Close();
            }

            __serial.Open();
        }

        public void Dispose()
        {
            __serial.Close();
            __serial.Dispose();
        }


        /// <summary>
        /// Shift 'n' right 'x' bits.
        /// </summary>
        /// <param name="n"></param>
        /// <param name="x"></param>
        /// <returns></returns>
        private uint rightShift(uint n, int x)
        {
            return n >> x & 0xFF;
        }

        /// <summary>
        /// Shifts 'n' left 'x' bits.
        /// </summary>
        /// <param name="n"></param>
        /// <param name="x"></param>
        /// <returns></returns>
        private uint leftShift(uint n, int x)
        {
            return n << x;
        }

        /// <summary>
        /// Get the bit of 'n' at position 'p'.
        /// </summary>
        /// <param name="n"></param>
        /// <param name="p"></param>
        /// <returns></returns>
        private int bitAtPosition(uint n, int p)
        {
            // A bitshift 2 ^ p
            uint twoP = (uint)(1 << p);

            // Binary AND composition (on both positions must be a 1)
            // This can only happen at position p
            if ((n & twoP) > 0)
            {
                return 1;
            }
            else
            {
                return 0;
            }
        }

        /// <summary>
        /// Writes a packet to the fingerprint sensor.
        /// </summary>
        /// <param name="packetType"></param>
        /// <param name="packetpayload"></param>
        private void writePacket(byte packetType, List<byte> packetpayload)
        {
            List<byte> packet = new List<byte>();
            // Write header (one byte at once)
            packet.Add((byte)rightShift(FINGERPRINT_STARTCODE, 8));
            packet.Add((byte)rightShift(FINGERPRINT_STARTCODE, 0));

            packet.Add((byte)rightShift(__address, 24));
            packet.Add((byte)rightShift(__address, 16));
            packet.Add((byte)rightShift(__address, 8));
            packet.Add((byte)rightShift(__address, 0));

            packet.Add(packetType);

            // The packet length = package payload (n bytes) + checksum (2 bytes)
            int packetLength = packetpayload.Count + 2;

            packet.Add((byte)rightShift((uint)packetLength, 8));
            packet.Add((byte)rightShift((uint)packetLength, 0));

            // The packet checksum = packet type(1 byte) + packet length(2 bytes) + payload(n bytes)
            uint packetChecksum = packetType + rightShift((uint)packetLength, 8) + rightShift((uint)packetLength, 0);

            // Write payload
            foreach(byte _byte in packetpayload)
            {
                packet.Add(_byte);
                packetChecksum += _byte;
            }

            // Write checksum (2 bytes)
            packet.Add((byte)rightShift(packetChecksum, 8));
            packet.Add((byte)rightShift(packetChecksum, 0));

            __serial.Write(packet.ToArray(), 0, packet.Count);
        }

        /// <summary>
        /// Receive a packet from the fingerprint sensor.
        /// </summary>
        /// <returns></returns>
        private Tuple<byte, List<byte>> readPacket()
        {
            List<byte> recievedPacketData = new List<byte>();
            int i = 0;

            while (true)
            {
                // Read one byte at a time. 
                // Can probably read all at once, optimization for another time
                try
                {
                    //var fragments = __serial.ReadExisting();
                    byte receivedFragemnt = (byte)__serial.ReadByte();
                    recievedPacketData.Add(receivedFragemnt);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
                i++;

                // Packet could be complete (the minimal packet size is 12 bytes)
                if (i >= 12)
                {
                    // Check the packet Header
                    if(recievedPacketData[0] != rightShift(FINGERPRINT_STARTCODE, 8) || recievedPacketData[1] != rightShift(FINGERPRINT_STARTCODE, 0))
                    {
                        throw new Exception("The received packet does not begin with a valid header!");
                    }

                    // Calculate packet payload length (combine the 2 length bytes)
                    uint packetPayloadLength = leftShift(recievedPacketData[7], 8) | leftShift(recievedPacketData[8], 0);

                    // Check if the packet is still fully received
                    // Condition: index counter < packet payload length + packet frame
                    if (i < packetPayloadLength + 9) continue;

                    // At this point the packet should be fully received
                    byte packetType = recievedPacketData[6];

                    // Calculate checksum:
                    // checksum = packet type (1 byte) + packet length (2 bytes) + packet payload (n bytes)
                    int packetChecksum = packetType + recievedPacketData[7] + recievedPacketData[8];

                    List<byte> packetPayload = new List<byte>();

                    var len = (int)packetPayloadLength - 2;
                    var range = Enumerable.Range(9, len);
                    // Collect package payload (ignore the last 2 checksum bytes)
                    foreach (int j in Enumerable.Range(9, len))
                    {
                        packetPayload.Add(recievedPacketData[j]);
                        packetChecksum += recievedPacketData[j];
                    }

                    // Calculate full checksum of the 2 separate checksum bytes
                    uint recievedChecksum = leftShift(recievedPacketData[i - 2], 8) | leftShift(recievedPacketData[i - 1], 0);

                    if(recievedChecksum != packetChecksum)
                    {
                        throw new Exception("The received packet is corrupted (the checksum is wrong)!");
                    }

                    return new Tuple<byte, List<byte>>(packetType, packetPayload);
                }
            }
        }

        /// <summary>
        /// Verify password of the fingerprint sensor.
        /// </summary>
        /// <returns></returns>
        public bool verifyPassword()
        {
            List<byte> packetPayload = new List<byte>() { FINGERPRINT_VERIFYPASSWORD,
                                                        (byte)rightShift(__password, 24),
                                                        (byte)rightShift(__password, 16),
                                                        (byte)rightShift(__password, 8),
                                                        (byte)rightShift(__password, 0)};

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if(receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ADDRCODE:
                    throw new Exception("The address is wrong");

                case FINGERPRINT_ERROR_WRONGPASSWORD:
                    return false;
                    
                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Set the password of the sensor.
        /// </summary>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        public bool setPassword (uint newPassword)
        {
            if (newPassword < 0x00000000 || newPassword > 0xFFFFFFFF)
            {
                throw new Exception("The given password is invalid!");
            }

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_SETPASSWORD,
                                                        (byte)rightShift(newPassword, 24),
                                                        (byte)rightShift(newPassword, 16),
                                                        (byte)rightShift(newPassword, 8),
                                                        (byte)rightShift(newPassword, 0)};

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch(receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    __password = newPassword;
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Set the module address of the sensor.
        /// </summary>
        /// <param name="newAddress"></param>
        /// <returns></returns>
        public bool setAddress(uint newAddress)
        {
            if (newAddress < 0x00000000 || newAddress > 0xFFFFFFFF)
            {
                throw new Exception("The given address is invalid!");
            }

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_SETADDRESS,
                                                        (byte)rightShift(newAddress, 24),
                                                        (byte)rightShift(newAddress, 16),
                                                        (byte)rightShift(newAddress, 8),
                                                        (byte)rightShift(newAddress, 0)};

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    __password = newAddress;
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Sets a system parameter of the sensor.
        /// </summary>
        /// <param name="parameterNumber"></param>
        /// <param name="parameterValue"></param>
        /// <returns></returns>
        public bool setSystemParameter(byte parameterNumber, byte parameterValue)
        {
            switch(parameterNumber)
            {
                case 4:
                    // Validate the baudrate parameter
                    if (parameterValue < 1 || parameterValue > 12 )
                    {
                        throw new Exception("The given baudrate parameter is invalid!");
                    }
                    break;

                case 5:
                    // Validate the security level parameter
                    if (parameterValue < 1 || parameterValue > 12)
                    {
                        throw new Exception("The given baudrate parameter is invalid!");
                    }
                    break;

                case 6:
                    // Validate the package length parameter
                    if (parameterValue < 1 || parameterValue > 12)
                    {
                        throw new Exception("The given baudrate parameter is invalid!");
                    }
                    break;

                default:
                    throw new Exception("The given parameter number is invalid!");
            }

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_SETSYSTEMPARAMETER,
                                                        parameterNumber,
                                                        parameterValue};

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_INVALIDREGISTER:
                    throw new Exception("Invalid register number");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Get all available system information of the sensor.
        /// </summary>
        /// <returns>A tuple containing(The system register(2 bytes), The system ID(2bytes), The storage capacity(2 bytes), The security level(2 bytes), The sensor address(4 bytes), The packet rate(2 bytes), The baudrate(2 bytes)).</returns>
        public Tuple<Int16, Int16, Int16, Int16, Int32, Int16, Int16> getSystemParameters()
        {
            List<byte> packetPayload = new List<byte>() { FINGERPRINT_GETSYSTEMPARAMETERS };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    Int16 statusRegister = (Int16)(leftShift(receivedPacketPayload[1], 8) | leftShift(receivedPacketPayload[2], 0));
                    Int16 systemID = (Int16)(leftShift(receivedPacketPayload[3], 8) | leftShift(receivedPacketPayload[4], 0));
                    Int16 storageCapacity = (Int16)(leftShift(receivedPacketPayload[5], 8) | leftShift(receivedPacketPayload[6], 0));
                    Int16 securityLevel = (Int16)(leftShift(receivedPacketPayload[7], 8) | leftShift(receivedPacketPayload[8], 0));
                    Int32 deviceAddress = ((receivedPacketPayload[9] << 8 | receivedPacketPayload[10]) << 8 | receivedPacketPayload[11]) << 8 | receivedPacketPayload[12];
                    Int16 packetLength = (Int16)(leftShift(receivedPacketPayload[13], 8) | leftShift(receivedPacketPayload[14], 0));
                    Int16 baudRate = (Int16)(leftShift(receivedPacketPayload[15], 8) | leftShift(receivedPacketPayload[16], 0));

                    return new Tuple<Int16, Int16, Int16, Int16, Int32, Int16, Int16>(statusRegister, systemID, storageCapacity, securityLevel, deviceAddress, packetLength, baudRate);

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Get a list of the template positions with usage indicator.
        /// </summary>
        /// <param name="page"></param>
        /// <returns></returns>
        public List<bool> getTemplateIndex(byte page)
        {
            if (page < 0 || page > 3)
            {
                throw new Exception("The given index page is invalid!");
            }

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_TEMPLATEINDEX,
                                                        page};

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    List<bool> templateIndex = new List<bool>();

                    // Contains the table page bytes (skip the first status byte)
                    byte pageElements = receivedPacketPayload[2];

                    foreach (var pageElement in pageElements.ToString())
                    {
                        // Test every bit (bit = template position is used indicator) of a table page element
                        foreach (int p in Enumerable.Range(0, 7 + 1))
                        {
                            bool positionIsUsed = bitAtPosition(pageElement, p) == 1;
                            templateIndex.Add(positionIsUsed);
                        }
                    }

                    return templateIndex;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Get the number of stored templates.
        /// </summary>
        /// <returns></returns>
        public Int16 getTemplateCount()
        {
            List<byte> packetPayload = new List<byte>() { FINGERPRINT_TEMPLATECOUNT };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    Int16 templateCount = (Int16)(leftShift(receivedPacketPayload[1], 8) | leftShift(receivedPacketPayload[2], 0));
                    return templateCount;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Read the image of a finger and stores it in ImageBuffer.
        /// </summary>
        /// <returns></returns>
        public bool readImage()
        {
            List<byte> packetPayload = new List<byte>() { FINGERPRINT_READIMAGE };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_READIMAGE:
                    throw new Exception("Could not read image");

                case FINGERPRINT_ERROR_NOFINGER:
                    return false;

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        //Look into implementing uploadImage()

        /// <summary>
        /// Saves a scanned finger at the given directory
        /// </summary>
        /// <param name="directory"></param>
        public void downloadImage(string directory)
        {
            List<byte> packetPayload = new List<byte>() { FINGERPRINT_DOWNLOADIMAGE };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    break;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_DOWNLOADIMAGE:
                    throw new Exception("Could not download image");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }

            List<byte> buffer = new List<byte>();
            int y = 0;
            int x = 0;

            while (receivedPacketType != FINGERPRINT_ENDDATAPACKET)
            {
                recievedPacket = readPacket();
                receivedPacketType = recievedPacket.Item1;
                receivedPacketPayload = recievedPacket.Item2;

                if (receivedPacketType != FINGERPRINT_DATAPACKET && receivedPacketType != FINGERPRINT_ENDDATAPACKET)
                {
                    throw new Exception("The received packet is not a data packet!");
                }                

                foreach (byte _byte in receivedPacketPayload)
                {
                    buffer.Add((byte)((_byte >> 4) * 17));
                    x++;

                    buffer.Add((byte)((_byte & 15) * 17));
                    x++;
                }

                y++;
            }
            x = x / y;

            WriteableBitmap wbm = new WriteableBitmap(x, y, 96, 96, PixelFormats.Gray8, null);
            wbm.WritePixels(new Int32Rect(0, 0, x, y), buffer.ToArray(), x, 0);

            // Look for way to return a usable bitmap (image is unusable/unsavable after memorystream is disposed)
            using (MemoryStream outStream = new MemoryStream())
            {
                BitmapEncoder enc = new BmpBitmapEncoder();
                enc.Frames.Add(BitmapFrame.Create((BitmapSource)wbm));
                enc.Save(outStream);
                Bitmap img = new Bitmap(outStream);
                img.Save(directory, ImageFormat.Bmp);
            }
        }

        /// <summary>
        /// Convert the image in ImageBuffer to finger characteristics and store in CharBuffer1 or CharBuffer2.
        /// </summary>
        /// <param name="charBufferNumber"></param>
        /// <returns></returns>
        public bool convertImage(byte charBufferNumber = 0x01)
        {
            if (charBufferNumber != 0x01 && charBufferNumber != 0x02)
            {
                throw new Exception("The given charbuffer number is invalid!");
            }

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_CONVERTIMAGE,
                                                        charBufferNumber};

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_MESSYIMAGE:
                    throw new Exception("The image is too messy");

                case FINGERPRINT_ERROR_FEWFEATUREPOINTS:
                    throw new Exception("The image contains too few feature points");

                case FINGERPRINT_ERROR_INVALIDIMAGE:
                    throw new Exception("The image is invalid");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Combine the characteristics which are stored in CharBuffer1 and CharBuffer2 to a template.
        /// The created template will be stored again in CharBuffer1 and CharBuffer2 as the same.
        /// </summary>
        /// <returns></returns>
        public bool createTemplate()
        {
            List<byte> packetPayload = new List<byte>() { FINGERPRINT_CREATETEMPLATE };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_CHARACTERISTICSMISMATCH:
                    return false;

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Save a template from the specified CharBuffer to the given position number.
        /// </summary>
        /// <param name="positionNumber"></param>
        /// <param name="charBufferNumber"></param>
        /// <returns></returns>
        public int storeTemplate(Int16 positionNumber = -1, byte charBufferNumber = 0x01)
        {
            // Find a free index
            if (positionNumber == -1)
            {
                foreach (int page in Enumerable.Range(0, 4))
                {
                    // Free index found?
                    if (positionNumber >= 0)
                    {
                        break;
                    }

                    List<bool> templateIndex = getTemplateIndex((byte)page);

                    foreach (int i in Enumerable.Range(0, templateIndex.Count))
                    {
                        // Index not used?
                        if (!templateIndex[i])
                        {
                            positionNumber = (Int16)((templateIndex.Count * page) + i);
                            break;
                        }
                    }
                }
            }

            if (positionNumber < 0x0000 || positionNumber >= getStorageCapacity())
            {
                throw new Exception("The given position number is invalid!");
            }

            if (charBufferNumber != 0x01 && charBufferNumber != 0x02)
            {
                throw new Exception("The given charbuffer number is invalid!");
            }

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_STORETEMPLATE,
                                                        charBufferNumber,
                                                        (byte)rightShift((uint)positionNumber, 8),
                                                        (byte)rightShift((uint)positionNumber, 0) };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return positionNumber;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_INVALIDPOSITION:
                    throw new Exception("Could not store template in that position");

                case FINGERPRINT_ERROR_FLASH:
                    throw new Exception("Error writing to flash");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Search the finger characteristics in CharBuffer in database.
        /// </summary>
        /// <returns></returns>
        public Tuple<Int16, Int16> searchTemplate()
        {
            // CharBuffer1 and CharBuffer2 are the same in this case
            byte charBufferNumber = 0x01;

            // Begin search at index 0
            uint positionStart = 0x0000;
            uint templatesCount = (uint)getStorageCapacity();

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_SEARCHTEMPLATE,
                                                        charBufferNumber,
                                                        (byte)rightShift(positionStart, 8),
                                                        (byte)rightShift(positionStart, 0),
                                                        (byte)rightShift(templatesCount, 8),
                                                        (byte)rightShift(templatesCount, 0) };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    Int16 poistionNumber = (Int16)(leftShift(receivedPacketPayload[1], 8) | leftShift(receivedPacketPayload[2], 0));
                    Int16 accuracyScore = (Int16)(leftShift(receivedPacketPayload[3], 8) | leftShift(receivedPacketPayload[4], 0));
                    return new Tuple<Int16, Int16>(poistionNumber, accuracyScore);

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_INVALIDPOSITION:
                    throw new Exception("Could not store template in that position");

                case FINGERPRINT_ERROR_NOTEMPLATEFOUND:
                    return new Tuple<Int16, Int16>(-1, -1);

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
            }

            /// <summary>
            /// Load an existing template specified by position number to specified CharBuffer.
            /// </summary>
            /// <param name="positionNumber"></param>
            /// <param name="charBufferNumber"></param>
            /// <returns></returns>
            public bool loadTemplate(uint positionNumber, byte charBufferNumber = 0x01)
        {
            if (positionNumber < 0x0000 || positionNumber >= getStorageCapacity())
            {
                throw new Exception("The given position number is invalid!");
            }

            if (charBufferNumber != 0x01 && charBufferNumber != 0x02)
            {
                throw new Exception("The given charbuffer number is invalid!");
            }

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_LOADTEMPLATE,
                                                        charBufferNumber,
                                                        (byte)rightShift(positionNumber, 8),
                                                        (byte)rightShift(positionNumber, 0) };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_LOADTEMPLATE:
                    throw new Exception("The template could not be read");

                case FINGERPRINT_ERROR_INVALIDPOSITION:
                    throw new Exception("Could not load template from that position");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }


        public bool deleteTemplate(uint positionNumber, uint count = 1)
        {
            if (positionNumber < 0x0000 || positionNumber >= getStorageCapacity())
            {
                throw new Exception("The given position number is invalid!");
            }

            if (count < 0x0000 | count > getStorageCapacity() - positionNumber)
            {
                throw new Exception("The given count is invalid!");
            }

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_DELETETEMPLATE,
                                                        (byte)rightShift(positionNumber, 8),
                                                        (byte)rightShift(positionNumber, 0),
                                                        (byte)rightShift(count, 8),
                                                        (byte)rightShift(count, 0) };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_INVALIDPOSITION:
                    throw new Exception("Invalid Position");

                case FINGERPRINT_ERROR_DELETETEMPLATE:
                    return false;

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Clear the complete template database.
        /// </summary>
        /// <returns></returns>
        public bool clearDatabase()
        {
            List<byte> packetPayload = new List<byte>() { FINGERPRINT_CLEARDATABASE };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return true;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_CLEARDATABASE:
                    return false;

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Compare the finger characteristics of CharBuffer1 with CharBuffer2 and return the accuracy score.
        /// </summary>
        /// <returns></returns>
        public Int16 compareCharacteristics()
        {
            List<byte> packetPayload = new List<byte>() { FINGERPRINT_COMPARECHARACTERISTICS };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    return (Int16)(leftShift(receivedPacketPayload[1], 8) | leftShift(receivedPacketPayload[2], 0));

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_NOTMATCHING:
                    return 0;

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }
        }

        /// <summary>
        /// Upload finger characteristics to CharBuffer1 or CharBuffer2.
        /// </summary>
        /// <param name="charBufferNumber"></param>
        /// <param name="characteristicsData"></param>
        /// <returns></returns>
        public bool uploadCharacteristics(byte charBufferNumber = 0x01, List<byte> characteristicsData = null)
        {
            if (charBufferNumber != 0x01 && charBufferNumber != 0x02)
            {
                throw new Exception("The given charbuffer number is invalid!");
            }

            if (characteristicsData.Count == 0)
            {
                throw new Exception("The characteristics data is required!");
            }

            int maxPacketSize = getMaxPacketSize();

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_UPLOADCHARACTERISTICS,
                                                        charBufferNumber};

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);

            // Get first reply packet
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    break;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_PACKETRESPONSEFAIL:
                    throw new Exception("Could not upload characteristics");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }

            // Upload data packets
            int packetNbr = characteristicsData.Count / maxPacketSize;

            if (packetNbr <= 1)
            {
                writePacket(FINGERPRINT_ENDDATAPACKET, characteristicsData);
            }
            else
            {
                int i = 1;
                int lfrom;
                int lto;

                while (i < packetNbr)
                {
                    lfrom = (i - 1) * maxPacketSize;
                    lto = lfrom + maxPacketSize;
                    writePacket(FINGERPRINT_DATAPACKET, characteristicsData.GetRange(lfrom, lto - lfrom));
                    i++;
                }

                lfrom = (i - 1) * maxPacketSize;
                lto = lfrom + maxPacketSize;
                writePacket(FINGERPRINT_ENDDATAPACKET, characteristicsData.GetRange(lfrom, lto - lfrom));
            }

            // Verify uploaded characteristics
            var characteristics = downloadCharacteristics(charBufferNumber);
            return (characteristics == characteristicsData);
        }

        /// <summary>
        /// Get the maximum allowed size of packet by sensor.
        /// </summary>
        /// <returns></returns>
        private int getMaxPacketSize()
        {
            switch(getSystemParameters().Item6)
            {
                case 1:
                    return 64;

                case 2:
                    return 128;

                case 3:
                    return 256;

                default:
                    return 32;
            }
        }

        /// <summary>
        /// Get the sensor storage capacity.
        /// </summary>
        /// <returns></returns>
        public short getStorageCapacity()
        {
            return getSystemParameters().Item3;
        }

        /// <summary>
        /// Generate a random 32-bit decimal number.
        /// </summary>
        /// <returns></returns>
        public uint generateRandomNumber()
        {
            List<byte> packetPayload = new List<byte>() { FINGERPRINT_GENERATERANDOMNUMBER };

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    break;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }

            uint number = 0;
            number = number | leftShift(receivedPacketPayload[1], 24);
            number = number | leftShift(receivedPacketPayload[2], 16);
            number = number | leftShift(receivedPacketPayload[3], 8);
            number = number | leftShift(receivedPacketPayload[4], 0);
            return number;
        }

        /// <summary>
        /// Download the finger characteristics of CharBuffer1 or CharBuffer2.
        /// </summary>
        /// <param name="charBufferNumber"></param>
        /// <returns></returns>
        public List<byte> downloadCharacteristics(byte charBufferNumber = 0x01)
        {
            if (charBufferNumber != 0x01 && charBufferNumber != 0x02)
            {
                throw new Exception("The given charbuffer number is invalid!");
            }

            List<byte> packetPayload = new List<byte>() { FINGERPRINT_DOWNLOADCHARACTERISTICS,
                                                        charBufferNumber};

            writePacket(FINGERPRINT_COMMANDPACKET, packetPayload);
            var recievedPacket = readPacket();

            byte receivedPacketType = recievedPacket.Item1;
            List<byte> receivedPacketPayload = recievedPacket.Item2;

            if (receivedPacketType != FINGERPRINT_ACKPACKET)
            {
                throw new Exception("The received packet is no ack packet!");
            }

            switch (receivedPacketPayload[0])
            {
                case FINGERPRINT_OK:
                    break;

                case FINGERPRINT_ERROR_COMMUNICATION:
                    throw new Exception("Communication error");

                case FINGERPRINT_ERROR_DOWNLOADCHARACTERISTICS:
                    throw new Exception("Could not download characteristics");

                default:
                    throw new Exception("Unknown error " + receivedPacketPayload[0].ToString("X"));
            }

            List<byte> completePayload = new List<byte>();

            while (receivedPacketType != FINGERPRINT_ENDDATAPACKET)
            {
                recievedPacket = readPacket();

                receivedPacketType = recievedPacket.Item1;
                receivedPacketPayload = recievedPacket.Item2;

                if (receivedPacketType != FINGERPRINT_DATAPACKET && receivedPacketType != FINGERPRINT_ENDDATAPACKET)
                {
                    throw new Exception("The received packet is not a data packet!");
                }

                foreach (byte _byte in receivedPacketPayload)
                {
                    completePayload.Add(_byte);
                }
            }

            return completePayload;
        }
    }
}
