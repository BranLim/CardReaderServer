using System;
using System.Collections.Generic;
using System.Linq;
using CardReaderServer.Mifare;
using CardReaderServer.models;
using Microsoft.AspNetCore.Mvc;
using PCSC;
using PCSC.Iso7816;
using System.Diagnostics;
using System.Text;
using PCSC.Exceptions;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace CardReaderServer.Controllers
{
    [ApiController]
    [Route("/api/cardreader")]
    public class CardReaderController : Controller
    {

        private const byte Manufacturer_MSB = 0x00;
        private const byte Manufacturer_LSB = 0x00;
        private const byte MifareClassic1kMSB = 0x00;
        private const byte MifareClassic1kLSB = 0x08;



        [HttpGet("cards")]
        public ActionResult<Response<models.SCCard>> GetCardInformation()
        {
            var response = new Response<models.SCCard>();

            var contextFactory = ContextFactory.Instance;
            using (var context = contextFactory.Establish(SCardScope.System))
            {
                var readerNames = context.GetReaders();
                if (readerNames == null || readerNames.Count() == 0)
                {
                    response.Status = "No card reader detected!";
                    return response;
                }

                try
                {
                    foreach (var readerName in readerNames)
                    {

                        var readerStatus = context.GetReaderStatus(readerName);

                        try
                        {
                            string uid;
                            byte[] cardAttributes = null;
                            using (var reader = context.ConnectReader(readerName, SCardShareMode.Shared, SCardProtocol.Any))
                            {
                                Console.WriteLine("Reader: " + reader.Name);
                                var status = reader.GetStatus();
                                var state = status.State;
                                if (!IsCardReady(state))
                                {
                                    Debug.WriteLine("Card not ready.");
                                    continue;
                                }
                                cardAttributes = status.GetAtr();

                                using (var isoReader = new IsoReader(
                                    context: context,
                                    readerName: readerName,
                                    mode: SCardShareMode.Shared,
                                    protocol: SCardProtocol.Any,
                                    releaseContextOnDispose: false))
                                {
                                    var card = new MifareCard(isoReader);

                                    var authSuccessful = card.Authenticate(Manufacturer_MSB, Manufacturer_MSB, KeyType.KeyA, 0x00);
                                    if (!authSuccessful)
                                    {
                                        throw new Exception("AUTHENTICATE failed.");
                                    }

                                    var result = card.ReadUID(Manufacturer_MSB, Manufacturer_LSB, 0);
                                    uid = (result != null)
                                        ? BitConverter.ToString(result)
                                        : null;

                                }

                            }


                            if (cardAttributes != null)
                            {
                                response.Status = "SUCCESS";
                                response.Data = new models.SCCard(uid, cardAttributes);
                            }


                        }
                        catch (PCSC.Exceptions.NoSmartcardException e)
                        {
                            Debug.WriteLine(string.Format("No smart card detected for reader {0}", readerName));
                        }

                    }

                }
                catch (Exception err) { }

            }


            return response;

        }

        [HttpPost("provision")]
        public ActionResult ProvisionUserIdentifier(User user)
        {
            if (user == null || string.IsNullOrEmpty(user.UserId) || !IsMultipleOf16(user.UserId.Length))
            {
                return new StatusCodeResult(400);
            }

            using (var context = ContextFactory.Instance.Establish(SCardScope.System))
            {
                var readerNames = context.GetReaders();
                if (IsEmpty(readerNames))
                {
                    return new StatusCodeResult(404);
                }

                foreach (var readerName in readerNames)
                {
                    var readerStatus = context.GetReaderStatus(readerName);
                    if (IsCardAvailable(readerStatus))
                    {
                        continue;
                    }
                    try
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

                            var updateSuccessful = card.UpdateBinary(MifareClassic1kMSB, MifareClassic1kLSB, Encoding.ASCII.GetBytes(user.UserId));
                            if (!updateSuccessful)
                            {
                                return new StatusCodeResult(400);
                            }
                        }
                    }
                    catch (NoSmartcardException err) { }
                }
            }

            return new StatusCodeResult(200);
        }

        [HttpGet("data")]
        public ActionResult<User> GetUserIdentifier(int dataLength)
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
                    var readerStatus = context.GetReaderStatus(readerName);
                    if (readerStatus.CurrentState == SCRState.Empty)
                    {
                        continue;
                    }
                    try
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

                            var data = card.ReadBinary(MifareClassic1kMSB, MifareClassic1kLSB, 32);
                            if (data == null)
                            {
                                return new StatusCodeResult(404);
                            }
                            var userId = Encoding.Default.GetString(data);
                            return new User { UserId = userId };
                        }
                    }
                    catch (NoSmartcardException err)
                    {
                        Debug.WriteLine("No smart card detected. Error: " + err.Message);
                    }

                }
                return new StatusCodeResult(404);
            }
        }

        private bool IsEmpty(ICollection<string> readerNames) => readerNames == null || readerNames.Count < 1;

        private bool IsMultipleOf16(int value) => value % 16 == 0;

        private bool IsCardAvailable(SCardReaderState cardState) => cardState.CurrentState != SCRState.Empty || cardState.CurrentState != SCRState.Present;

        private bool IsCardReady(SCardState cardState) => cardState == (SCardState.Present | SCardState.Powered | SCardState.Specific);

    }
}

