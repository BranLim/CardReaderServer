using System;
namespace CardReaderServer.exceptions
{
    public class NoCardReaderException : Exception
    {
        public NoCardReaderException() : base("No card reader connected or found.")
        {

        }
    }
}
