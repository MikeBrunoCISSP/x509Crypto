using System;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Windows.Forms;

namespace Tester {
    class Program {
        [STAThread]
        static void Main(string[] args) {
            serializeCert();
        }

        static void serializeCert() {
            using (X509Store store = new X509Store(StoreLocation.CurrentUser)) {
                store.Open(OpenFlags.ReadOnly);
                var cert = store.Certificates.Find(X509FindType.FindByThumbprint, "F43215713A8B91FEE14015D38CA14CCB4A05733C", false);
                if (cert != null) {
                    var resources = new Resources {
                        CertBytes = cert.Export(X509ContentType.Pkcs12)
                    };
                    string json = JsonSerializer.Serialize(resources);
                    Clipboard.SetText(json);
                }
            }
        }

        static void deSerializeCert() {
            string json = "{\"Certificate\":\"MIIDngIBAzCCA1oGCSqGSIb3DQEHAaCCA0sEggNHMIIDQzCCAz8GCSqGSIb3DQEHBqCCAzAwggMsAgEAMIIDJQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQI2R6Yk6zlvccCAgfQgIIC+ELlDMDYDKPq/qZ/Zs8P2tyAkx9W6Q9m/wknJyrzg1kJFIinLKFxTwPPSgw+a+WwxWd5kGw6xxq3zA1Moid/S7kO1g/MlQk18PAEXBtA//2u0pj4k4rnCxhjoNOmZxlxgYr0xllB7+nmG8HkpWQQxhQObmzVLDFCIZTDcjL78wFk1xS0lYIB6OrqnxDzsaDWCA1BEpGxpdwHjU8Iwjm0u+0icBYSFtayUo1a4h5/4KGpLweH3oRJ3+2OkXZfuRlpdf4PW2sZ+EBvYOfEAw4Fh/KavskRQrrwUZ+wtvP0bcTr5f7NzF5YQ879oxuTRMDAbYph1f+ZTP9G6qnHVY9guE+o6OIJYx+wDQcZR4WDHjD9MbrvN/x2s7iuMFJXsW9D0MkjWCwxsTrUV6Xa2N2sjp5uumn1EyDSY1Fr0fpG/ZzOvrA5HeEqc4PmnT/w4FUMlDrgRNoMQDDwvMqyJ1OofhrSKGCm+STXtYKMS5087o+v6UkXiWmfX9y/pHsT/aDc7OhAp4GlfMyMmruCIAOakKCUJQXYkkGyx3rxrhrfhV+S+shOwImatZ2X35dC5RqqkqIPPu5+YxcQ3B5YiZZX0l00LURkpwktXAJdjxro1kzlFBvWoSWTEiDaxy3/uC0hcfFt79Wd4Gs6z9JRu+QZ7BUsQ09bF0YAq543HJ4qIsPCFEbAK8Tqkp/PFfMbYDtQhXWUBz2AMlO887LMpNoL5weWMCLPupD/lIGhHEM11EQ2EWSrNN6e5FfV5Hxa5FGMfyMT+lwppuNWPd5c1PuoubDKd6tvU/1TWwCEhc3xau/BbTvQiXEJMfRw9x3EYChDm/i7roRSHItyIU0L9AR4POvGIm75dDsYXEwnQBQoTBP238TsurFr+O3lYEGrdPpBm5LeBgBALAg5Q9Xx3WClmd2uXdmdI6rijoqLF36Y6FSb/rlVBidTZknMCN+WL+R7tN992ScQOrvw+sZXfIhwehD+zw0ovT9rtaRvzduoVDZaSSlImOHbQ2EwOzAfMAcGBSsOAwIaBBSCH1bKiBE6+EjYUt1MZeEMDPlsWwQUsU5pAPey57kuPwyCdhFQF1mGRgICAgfQ\"}";
            Resources resources = JsonSerializer.Deserialize<Resources>(json);
            var myCert = new X509Certificate2(resources.CertBytes);
            Console.WriteLine(myCert.Thumbprint);
            Console.ReadKey();
        }

        class Resources {
            public byte[] CertBytes { get; set; }
        }
    }
}
