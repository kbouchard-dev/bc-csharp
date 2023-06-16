using System.IO;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cms
{
    public class Pkcs7ProcessableObject : CmsProcessable
    {
        public Asn1Object Type { get; }
        public Asn1Encodable Structure { get; }

        public Pkcs7ProcessableObject(Asn1Object type, Asn1Encodable structure)
        {
            this.Type = type;
            this.Structure = structure;
        }

        public void Write(Stream outStream)
        {
            if (Structure is Asn1Sequence)
            {
                Asn1Sequence s = Asn1Sequence.GetInstance(Structure);

                foreach (Asn1Encodable encodable in s)
                {
                    byte[] encoded = encodable.ToAsn1Object().GetEncoded(Asn1Encodable.Der);
                    outStream.Write(encoded, 0, encoded.Length);
                }
            }
            else
            {
                byte[] encoded = Structure.ToAsn1Object().GetEncoded(Asn1Encodable.Der);
                int index = 1;

                while ((encoded[index] & 0xff) > 127)
                {
                    ++index;
                }

                ++index;

                outStream.Write(encoded, index, encoded.Length - index);
            }
        }
    }
}
