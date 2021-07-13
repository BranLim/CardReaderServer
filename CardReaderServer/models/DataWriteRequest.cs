using System;
namespace CardReaderServer.models
{
    public class DataWriteRequest: CardReaderRequest
    {
        public string Data { get; set; }
    }
}
