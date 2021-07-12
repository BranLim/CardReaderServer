using System;
namespace CardReaderServer.models
{
    public class Response<T>
    {
        public Response()
        {
        }

        public string Status { get; set; }

        public T Data { get; set; }
    }
}
