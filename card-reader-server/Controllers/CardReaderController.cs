using System.Collections.Generic;
using System.Text;
using CardReaderServer.Mifare;
using Microsoft.AspNetCore.Mvc;
using PCSC;
using PCSC.Iso7816;


// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace CardReaderServer.Controllers
{

    public class CardReaderController : Controller
    {
        private const byte MifareClassic1kMSB = 0x00;
        private const byte MifareClassic1kLSB = 0x08;

        public ActionResult ProvisionUserIdentifier(string userId)
        {
            using (var context = ContextFactory.Instance.Establish(SCardScope.System))
            {
                var readerNames = context.GetReaders();
                if (IsEmpty(readerNames))
                {
                    return new StatusCodeResult(404);
                }
                foreach (var readerName in readerNames)
                {
                    using (var isoReader = new IsoReader(
                        context: context,
                        readerName: readerName,
                        mode: SCardShareMode.Shared,
                        protocol: SCardProtocol.Any,
                        releaseContextOnDispose: false))
                    {

                        var card = new MifareCard(isoReader);

                        var authSuccessful = card.Authenticate(MifareClassic1kMSB, MifareClassic1kLSB, KeyType.KeyA, 0x00);
                        if (!authSuccessful)
                        {
                            return new StatusCodeResult(403);
                        }

                        var updateSuccessful = card.UpdateBinary(MifareClassic1kMSB, MifareClassic1kLSB, Encoding.ASCII.GetBytes(userId));
                        if (!updateSuccessful)
                        {
                            return new StatusCodeResult(400);
                        }

                    }
                }


            }

            return new StatusCodeResult(200);
        }


        private bool IsEmpty(ICollection<string> readerNames) => readerNames == null || readerNames.Count < 1;
    }

}
