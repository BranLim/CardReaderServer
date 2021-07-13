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
using Microsoft.AspNetCore.Http;

// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace CardReaderServer.Controllers
{
    [ApiController]
    [Route("/api/cardreader")]
    public class CardReaderController : Controller
    {
        /*
         * Sector 0, Block 0
         */
        private const byte Manufacturer_MSB = 0x00;
        private const byte Manufacturer_LSB = 0x00;


        /*
         * Sector 2, Block 0
         */
        private const byte MifareClassic1kMSB = 0x00;
        private const byte MifareClassic1kLSB = 0x08;



        [HttpGet("cards")]
        public IActionResult GetCardInformation()
        {
            string uid;
            byte[] cardAttributes = null;

            var contextFactory = ContextFactory.Instance;
            using (var context = contextFactory.Establish(SCardScope.System))
            {
                var readerNames = context.GetReaders();
                if (IsEmpty(readerNames))
                {
                    Response.StatusCode = StatusCodes.Status404NotFound;
                    return new JsonResult(new CardReaderResponse { Status = CardReaderResponseStatus.ERROR, Message = "No card reader detected." });
                }


                foreach (var readerName in readerNames)
                {
                    try
                    {
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
                                if (authSuccessful)
                                {
                                    var result = card.ReadUID(Manufacturer_MSB, Manufacturer_LSB, 0);
                                    uid = (result != null)
                                        ? BitConverter.ToString(result)
                                        : null;

                                    Response.StatusCode = StatusCodes.Status200OK;
                                    return new JsonResult(new SCCardResponse(uid, cardAttributes, readerName)
                                    {
                                        Status = CardReaderResponseStatus.SUCCESS,
                                        Message = ""
                                    });
                                }
                            }

                        }

                    }
                    catch (NoSmartcardException e)
                    {
                        Debug.WriteLine(string.Format("No smart card detected for reader {0}", readerName));
                    }
                    catch (Exception err)
                    {
                        Debug.WriteLine(string.Format("Error trying to detect smart card. Error: ", err.Message));
                    }

                }
            }
            Response.StatusCode = StatusCodes.Status500InternalServerError;
            return new JsonResult(new CardReaderResponse { Status = CardReaderResponseStatus.ERROR, Message = "No card reader/smart card detected!" });

        }

        [HttpPost("card/data")]
        public IActionResult WriteDataToCard(DataWriteRequest dataWriteRequest)
        {            
            if (string.IsNullOrEmpty(dataWriteRequest.Data) || !IsMultipleOf16(dataWriteRequest.Data.Length))
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return new JsonResult(new CardReaderResponse
                {
                    Status = CardReaderResponseStatus.ERROR,
                    Message = "Missing or invalid data. Should be of length in multiples of 16 (e.g. 16, 32, 48)"
                });
            }
            

            using (var context = ContextFactory.Instance.Establish(SCardScope.System))
            {
                var readerNames = context.GetReaders();
                if (IsEmpty(readerNames))
                {
                    Response.StatusCode = StatusCodes.Status404NotFound;
                    return new JsonResult(new CardReaderResponse { Status = CardReaderResponseStatus.ERROR, Message = "No card reader detected." });
                }
                
                foreach (var reader in readerNames)
                {
                    try
                    {
                        string uid = null;
                        byte[] data = Encoding.ASCII.GetBytes(dataWriteRequest.Data);
                        using (var isoReader = new IsoReader(context: context, readerName: reader, mode: SCardShareMode.Shared, protocol: SCardProtocol.Any, releaseContextOnDispose: false))
                        {
                            var card = new MifareCard(isoReader);

                            var authSuccessful = card.Authenticate(MifareClassic1kMSB, MifareClassic1kLSB, KeyType.KeyA, 0x00);
                            if (!authSuccessful)
                            {
                                Response.StatusCode = StatusCodes.Status403Forbidden;
                                return new JsonResult(new CardReaderResponse { Status = CardReaderResponseStatus.ERROR, Message = "Card reader cannot authenticate smart card" });
                            }

                            var result = card.ReadUID(Manufacturer_MSB, Manufacturer_LSB, 0);
                            uid = (result != null)
                                ? BitConverter.ToString(result)
                                : null;

                            var updateSuccessful = card.UpdateBinary(MifareClassic1kMSB, MifareClassic1kLSB, data);
                            if (!updateSuccessful)
                            {
                                Response.StatusCode = StatusCodes.Status500InternalServerError;
                                return new JsonResult(new CardReaderResponse { Status = CardReaderResponseStatus.ERROR, Message = "Error writing data to smart card." });
                            }

                            Response.StatusCode = StatusCodes.Status200OK;
                            return new JsonResult(new DataResponse
                            {
                                Status = CardReaderResponseStatus.SUCCESS,
                                Message = "",
                                CardUID = uid,
                                CardReader = reader,
                                Content = dataWriteRequest.Data,
                                DataLength = data?.Length ?? 0
                            });
                        }
                    }
                    catch (NoSmartcardException err)
                    {
                        Debug.WriteLine(string.Format("No smart card detected. Error: {0}", err.Message));                       
                    }
                    catch (Exception err)
                    {
                        Debug.WriteLine(string.Format("Error writing to smart card. Error: {0}", err.Message));
                       
                    }
                }
                
            }
            Response.StatusCode = StatusCodes.Status500InternalServerError;
            return new JsonResult(new CardReaderResponse { Status = CardReaderResponseStatus.ERROR, Message = "Error writing data to smart card. It might not be available or detected." });
        }

        [HttpGet("card/data")]
        public IActionResult ReadDataFromCard(DataReadRequest dataReadRequest)
        {

            if (!IsMultipleOf16(dataReadRequest.DataLength))
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return new JsonResult(new CardReaderResponse
                {
                    Status = CardReaderResponseStatus.ERROR,
                    Message = "Data length should be multiples of 16 (e.g. 16, 32, 48)"
                });
            }

            using (var context = ContextFactory.Instance.Establish(SCardScope.System))
            {

                var readerStatus = context.GetReaderStatus(dataReadRequest.CardReader);
                if (!IsCardAvailable(readerStatus))
                {
                    Response.StatusCode = StatusCodes.Status404NotFound;
                    return new JsonResult(new CardReaderResponse { Status = CardReaderResponseStatus.ERROR, Message = "Card reader not available" });
                }

                try
                {
                    using (var isoReader = new IsoReader(context: context, readerName: dataReadRequest.CardReader, mode: SCardShareMode.Shared, protocol: SCardProtocol.Any, releaseContextOnDispose: false))
                    {
                        var card = new MifareCard(isoReader);

                        var authSuccessful = card.Authenticate(MifareClassic1kMSB, MifareClassic1kLSB, KeyType.KeyA, 0x00);
                        if (!authSuccessful)
                        {
                            Response.StatusCode = StatusCodes.Status403Forbidden;
                            return new JsonResult(new CardReaderResponse { Status = CardReaderResponseStatus.ERROR, Message = "Card reader cannot authenticate smart card" });
                        }

                        var result = card.ReadUID(Manufacturer_MSB, Manufacturer_LSB, 0);
                        string uid = (result != null)
                            ? BitConverter.ToString(result)
                            : null;


                        var data = card.ReadBinary(MifareClassic1kMSB, MifareClassic1kLSB, dataReadRequest.DataLength);
                        string content = (data == null ? "" : Encoding.Default.GetString(data));

                        Response.StatusCode = StatusCodes.Status200OK;
                        return new JsonResult(new DataResponse
                        {
                            Status = CardReaderResponseStatus.SUCCESS,
                            Message = "",
                            CardUID = uid,
                            CardReader = dataReadRequest.CardReader,
                            Content = content,
                            DataLength = data?.Length ?? 0
                        });
                    }
                }
                catch (NoSmartcardException err)
                {
                    Debug.WriteLine(string.Format("No smart card detected. Error: {0}", err.Message));                  
                }
                catch (Exception err)
                {
                    Debug.WriteLine(string.Format("Error writing to smart card. Error: {0}", err.Message));                  
                }
            }
            Response.StatusCode = StatusCodes.Status500InternalServerError;
            return new JsonResult(new CardReaderResponse { Status = CardReaderResponseStatus.ERROR, Message = "Error reading data from smart card. It might not be available or detected." });
        }



        private bool IsEmpty(ICollection<string> readerNames) => readerNames == null || readerNames.Count < 1;

        private bool IsMultipleOf16(int value) => value % 16 == 0;

        private bool IsCardAvailable(SCardReaderState cardState) => cardState.CurrentState != SCRState.Empty || cardState.CurrentState != SCRState.Present;

        private bool IsCardReady(SCardState cardState) => cardState == (SCardState.Present | SCardState.Powered | SCardState.Specific) || cardState == SCardState.Specific;

    }
}

