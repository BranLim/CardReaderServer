using System;
namespace CardReaderServer.acs
{
    public enum KeyStructure : byte
    {
        VolatileMemory = 0x00,
        NonVolatileMemory = 0x20
    }
}
