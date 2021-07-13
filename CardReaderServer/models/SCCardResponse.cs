using System;
namespace CardReaderServer.models
{
    public class SCCardResponse: CardReaderResponse
    {
        public SCCardResponse(string uid, byte[] cardAttr, string readerName)
        {
            ID = uid;

            byte[] rid = new byte[5];
            Array.Copy(cardAttr, 7, rid, 0, 5);
            RID = RidToReadableName(rid);

            byte[] name = new byte[2];
            Array.Copy(cardAttr, 14, name, 0, 2);
            CardType = CardNameToUserReadableName(name);

            ReaderName = readerName;
        }


        public string ID { get; private set; }

        public string RID { get; private set; }

        public string CardType { get; private set; }

        public string ReaderName { get; private set; }


        private string CardNameToUserReadableName(byte[] cardName)
        {
            int name = BitConverter.ToInt16(cardName, 0);

            switch (name)
            {
                case 1:
                    return "MIFARE Classic 1K";
                case 2:
                    return "MIFARE Classic 4K";
                default:
                    return "Unknown";

            }
        }

        private string RidToReadableName(byte[] rid)
        {
            var converted = BitConverter.ToString(rid);
            converted = converted.Replace("-", "");
            switch (converted)
            {
                case "A000000306":
                    return "PS / SC Workgroup";
                case "A000000396":
                    return "NXP Semiconductors Germany GmbH";
                default:
                    return "Unknown Vendor";
            }
        }

    }
}
