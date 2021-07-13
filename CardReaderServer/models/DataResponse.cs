
namespace CardReaderServer.models
{
    public class DataResponse: CardReaderResponse
    {
        public DataResponse()
        {
        }

        public string CardUID { get; set; }
        public string CardReader { get; set; }
        public int DataLength { get; set; }
        public string Content { get; set; }


    }
}
