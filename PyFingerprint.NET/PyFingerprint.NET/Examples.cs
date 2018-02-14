using System;
using System.Threading;

namespace PyFingerprint_dotNET.Examples
{
    public static class Examples
    {
        public static void example_enroll()
        {
            try
            {
                using (PyFingerprint_dotNET scanner = new PyFingerprint_dotNET())
                {
                    if (!scanner.verifyPassword())
                    {
                        throw new Exception("The given fingerprint sensor password is wrong!");
                    }

                    Console.WriteLine("Currently used templates: " + scanner.getTemplateCount() + "/" + scanner.getStorageCapacity());

                    try
                    {
                        Console.WriteLine("Waiting for finger...");

                        while (!scanner.readImage())
                        {
                            // Check for finger once a second
                            Thread.Sleep(1000);
                        }

                        scanner.convertImage(0x01);

                        var result = scanner.searchTemplate();
                        int positionNumber = result.Item1;

                        if (positionNumber >= 0)
                        {
                            Console.WriteLine("Template already exists at position # " + positionNumber);
                            return;
                        }

                        Console.WriteLine("Remove finger...");
                        Thread.Sleep(2000);

                        Console.WriteLine("Waiting for same finger again...");

                        while (!scanner.readImage())
                        {
                            // Check for finger once a second
                            Thread.Sleep(1000);
                        }

                        scanner.convertImage(0x02);

                        if (scanner.compareCharacteristics() == 0)
                        {
                            throw new Exception("Fingerprints do not match!");
                        }

                        scanner.createTemplate();

                        positionNumber = scanner.storeTemplate();
                        Console.WriteLine("Finger enrolled sucessfully!");
                        Console.WriteLine("New template position # " + positionNumber);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Operation failed!");
                        Console.WriteLine("Exception message: " + ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("The fingerprint sensor could not be initialized!");
                Console.WriteLine("Exception message: " + ex.Message);
            }
        }


        public static void example_search()
        {
            try
            {
                using (PyFingerprint_dotNET scanner = new PyFingerprint_dotNET())
                {
                    if (!scanner.verifyPassword())
                    {
                        throw new Exception("The given fingerprint sensor password is wrong!");
                    }

                    try
                    {
                        Console.WriteLine("Waiting for finger...");

                        while (!scanner.readImage())
                        {
                            // Check for finger once a second
                            Thread.Sleep(1000);
                        }

                        scanner.convertImage(0x01);

                        var result = scanner.searchTemplate();
                        int positionNumber = result.Item1;
                        int accuracyScore = result.Item2;

                        if (positionNumber == -1)
                        {
                            Console.WriteLine("No Template Found");
                            //return;
                        }
                        else
                        {
                            Console.WriteLine("Found template at position # " + positionNumber);
                            Console.WriteLine("The accuracy score is: " + accuracyScore);
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Operation failed!");
                        Console.WriteLine("Exception message: " + ex.Message);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("The fingerprint sensor could not be initialized!");
                Console.WriteLine("Exception message: " + ex.Message);
            }
        }
    }
}
