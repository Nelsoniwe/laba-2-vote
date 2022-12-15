using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace laba2_vote.Models
{
    public class CVK
    {
        UnicodeEncoding byteConverter = new UnicodeEncoding();

        public RSAParameters Key { get; set; } = new RSACryptoServiceProvider(1024).ExportParameters(true);
        private static RSACryptoServiceProvider encryptionKey = new RSACryptoServiceProvider(1536);
        public List<Person> People { get; set; } = new List<Person>();

        private List<Vote> Votes { get; set; } = new List<Vote>();

        private string personsPath;
        private string votesPath;

        public CVK(string PersonsPath, string VotesPath)
        {
            personsPath = PersonsPath;
            votesPath = VotesPath;

        }

        public void Load()
        {
            FileInfo fi = new FileInfo(personsPath);
            FileStream fs = fi.Open(FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);

            using (StreamReader r = new StreamReader(fs))
            {
                string json = r.ReadToEnd();
                if (json != "")
                {
                    People = JsonSerializer.Deserialize<List<Person>>(json);
                }
            }

            fi = new FileInfo(votesPath);
            fs = fi.Open(FileMode.OpenOrCreate, FileAccess.Read, FileShare.Read);

            using (StreamReader r = new StreamReader(fs))
            {
                string json = r.ReadToEnd();
                if (json != "")
                {
                    Votes = JsonSerializer.Deserialize<List<Vote>>(json);
                }
            }
        }


        public void Save()
        {
            string jsonPeople = JsonSerializer.Serialize(People);
            File.WriteAllText(personsPath, jsonPeople);

            string jsonVotes = JsonSerializer.Serialize(Votes);
            File.WriteAllText(votesPath, jsonVotes);
        }

        public Tuple<List<VoteAndSign>, RSAParameters> CheckPackets(List<List<VoteAndKey>> packets)
        {
            List<VoteAndKey> lastPacket = packets[0];
            packets.RemoveAt(0);

            byte[] firstEncMessage = packets[0][0].Message;
            RSACryptoServiceProvider key = packets[0][0].Key;
            byte[] firstDecMessage = key.Decrypt(firstEncMessage, false);
            string bufferMessage = Encoding.UTF8.GetString(firstDecMessage);
            string[] words = bufferMessage.Split(' ');
            string id = words[0];

            if (People.FirstOrDefault(x => x.Id == id).BulleteneSended)
            {
                return null;
            }

            foreach (var item in packets)
            {
                foreach (var itemAndKey in item)
                {
                    string message = Encoding.UTF8.GetString(
                        itemAndKey.Key.Decrypt(
                            itemAndKey.Message, false));
                    var bulleteneUserId = message.Split(' ')[0];

                    if (bulleteneUserId != id)
                    {
                        return null;
                    }
                }
            }

            People.FirstOrDefault(x => x.Id == id).BulleteneSended = true;

            List<VoteAndSign> signedPackets = new List<VoteAndSign>();

            foreach (var encryptedMessageAndKey in lastPacket)
            {
                RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
                RSAalg.ImportParameters(Key);
                var sign = RSAalg.SignData(encryptedMessageAndKey.Message, SHA256.Create());

                signedPackets.Add(new VoteAndSign(encryptedMessageAndKey.Message, sign));
            }

            return Tuple.Create(signedPackets, encryptionKey.ExportParameters(false));
        }

        public bool Vote(VoteAndKey voteAndKey, byte[] sign)
        {
            var message = Encoding.UTF8.GetString(voteAndKey.Key.Decrypt(voteAndKey.Message, false));

            RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

            RSAalg.ImportParameters(Key);

            if (!RSAalg.VerifyData(voteAndKey.Message, SHA256.Create(), sign))
            {
                return false;
            }

            var voter = message.Split(' ')[0];
            var applicant = message.Split(' ')[1];

            if (People.FirstOrDefault(x => x.Id == voter) == null)
            {
                return false;
            }

            Votes.Add(new Vote(voter,applicant));
            return true;
        }

        public int GetVotesById(string id)
        {
            var applicant = People.FirstOrDefault(x => x.Id == id && x.Role == Role.applicant);
            if (applicant != null)
                return Votes.Where(x => x.ForWho == id).Count();
            return 0;
        }
    }
}
