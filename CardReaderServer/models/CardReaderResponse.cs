
namespace CardReaderServer.models
{
    public class CardReaderResponseStatus
    {
        public const string ERROR = "ERROR";
        public const string SUCCESS = "SUCCESS";
    }

    public class CardReaderResponse
    {
        public CardReaderResponse()
        {
        }

        public string Status { get; set; }

        public string Message { get; set; }

    }
}
