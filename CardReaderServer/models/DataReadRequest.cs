using System;
namespace CardReaderServer.models
{
    public class DataReadRequest: CardReaderRequest
    {
        public DataReadRequest()
        {
        }

        public int DataLength { get; set; }
    }
}
