using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Data.Entity;
using System.Data;

using System.Net;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;

namespace BankApplication.Extra
{
    public static class VisualCryptographyLibrary
    {
        private const int GENERATE_IMAGE_COUNT = 2;
        private static Bitmap[] m_EncryptedImages;

        public const string SHARE_1_NAME = "share1.jpg";
        public const string SHARE_2_NAME = "share2.jpg";
        public const string TEMP_SHARE_1_NAME = "Tempshare1.bmp";
        public const string TEMP_SHARE_2_NAME = "Tempshare2.bmp";

        public static void processing(String fullPath, String stamp)
        {
            //string fullPath = Path.Combine(HttpContext.Current.Server.MapPath("~/Images/test.jpg"));
            Bitmap temp = ConvertToBitmap(fullPath);
            //bt.Save(Path.Combine(HttpContext.Current.Server.MapPath("~/Images/test1.bmp")));
            Bitmap source = new Bitmap(temp.Width, temp.Height);

            Graphics g = Graphics.FromImage(source);
            g.DrawImage(temp, 0, 0);
            List<Color> palette = new List<Color>();
            palette.Add(Color.FromArgb(0, 0, 0));
            palette.Add(Color.FromArgb(255, 255, 255));
            Bitmap gSource = ConvertToGrayscale(source);
            Bitmap bwSource = FloydSteinbergDither.Process(gSource, palette.ToArray());
            m_EncryptedImages = GenerateImage(source);
            m_EncryptedImages[0].Save(Path.Combine(HttpContext.Current.Server.MapPath("~/" + stamp + SHARE_1_NAME)), System.Drawing.Imaging.ImageFormat.Jpeg);
            m_EncryptedImages[1].Save(Path.Combine(HttpContext.Current.Server.MapPath("~/" + stamp + SHARE_2_NAME)), System.Drawing.Imaging.ImageFormat.Jpeg);
            m_EncryptedImages[0].Save(Path.Combine(HttpContext.Current.Server.MapPath("~/" + stamp + TEMP_SHARE_1_NAME)));
            m_EncryptedImages[1].Save(Path.Combine(HttpContext.Current.Server.MapPath("~/" + stamp + TEMP_SHARE_2_NAME)));
        }

        public static bool comparTwoPhotos(string path1, string path2)
        {
            string orginalPath = Path.Combine(HttpContext.Current.Server.MapPath("~/Images"), path1);
            string temppath = Path.Combine(HttpContext.Current.Server.MapPath("~/Temp"), path2);
            Bitmap orginalImage = ConvertToBitmap(orginalPath);
            Bitmap newImage = ConvertToBitmap(temppath);
            if (CompareBitmapsLazy(orginalImage, newImage))
                return true;
            return false;
        }
        public static Bitmap ConvertToBitmap(string fileName)
        {
            Bitmap bitmap;
            using (Stream bmpStream = System.IO.File.Open(fileName, System.IO.FileMode.Open))
            {
                Image image = Image.FromStream(bmpStream);

                bitmap = new Bitmap(image);

            }
            return bitmap;
        }

        private static Bitmap ConvertToGrayscale(Bitmap source)
        {
            int sourceWidth = source.Width;
            int sourceHeight = source.Height;
            Bitmap result = new Bitmap(sourceWidth, sourceHeight);
            for (int y = 0; y < sourceHeight; y++)
            {
                for (int x = 0; x < sourceWidth; x++)
                {
                    Color c = source.GetPixel(x, y);
                    int luma = (int)(c.R * 0.3 + c.G * 0.59 + c.B * 0.11);
                    result.SetPixel(x, y, Color.FromArgb(luma, luma, luma));
                }
            }
            return result;
        }

        private static Bitmap ConvertToBackAndWhite(Bitmap source)
        {
            int sourceWidth = source.Width;
            int sourceHeight = source.Height;

            Bitmap result = new Bitmap(sourceWidth, sourceHeight);
            double mid = 255d * (1d / 2d);

            for (int x = 0; x < sourceWidth; x++)
            {
                for (int y = 0; y < sourceHeight; y++)
                {
                    Color c = source.GetPixel(x, y);
                    c = (Average(c.R, c.G, c.B) > mid) ? Color.Empty : Color.Black;
                    result.SetPixel(x, y, c);
                }
            }

            return result;
        }
        private static double Average(params int[] inputList)
        {
            double total = 0;
            foreach (var num in inputList)
            {
                total += num;
            }

            return total / inputList.Length;
        }
        private static Bitmap[] GenerateImage(Bitmap source)
        {
            int sourceWidth = source.Width;
            int sourceHeight = source.Height;

            Bitmap tempImage = new Bitmap(sourceWidth / 2, sourceHeight);
            Bitmap[] image = new Bitmap[GENERATE_IMAGE_COUNT];

            Random rand = new Random();
            SolidBrush brush = new SolidBrush(Color.Black);
            Point mid = new Point(sourceWidth / 2, sourceHeight / 2);

            Graphics gtemp = Graphics.FromImage(tempImage);

            Color foreColor;

            gtemp.DrawImage(source, 0, 0, tempImage.Width, tempImage.Height);


            for (int i = 0; i < image.Length; i++)
            {
                image[i] = new Bitmap(sourceWidth, sourceHeight);
            }


            int index = -1;
            int width = tempImage.Width;
            int height = tempImage.Height;
            for (int x = 0; x < width; x += 1)
            {
                for (int y = 0; y < height; y += 1)
                {
                    foreColor = tempImage.GetPixel(x, y);
                    index = rand.Next(image.Length);
                    if (foreColor.ToArgb() == Color.Empty.ToArgb() || foreColor.ToArgb() == Color.White.ToArgb())
                    {
                        for (int i = 0; i < image.Length; i++)
                        {
                            if (index == 0)
                            {
                                image[i].SetPixel(x * 2, y, Color.Black);
                                image[i].SetPixel(x * 2 + 1, y, Color.Empty);
                            }
                            else
                            {
                                image[i].SetPixel(x * 2, y, Color.Empty);
                                image[i].SetPixel(x * 2 + 1, y, Color.Black);
                            }
                        }
                    }
                    else
                    {
                        for (int i = 0; i < image.Length; i++)
                        {
                            if ((index + i) % image.Length == 0)
                            {
                                image[i].SetPixel(x * 2, y, Color.Black);
                                image[i].SetPixel(x * 2 + 1, y, Color.Empty);
                            }
                            else
                            {
                                image[i].SetPixel(x * 2, y, Color.Empty);
                                image[i].SetPixel(x * 2 + 1, y, Color.Black);
                            }
                        }
                    }
                }
            }

            brush.Dispose();
            tempImage.Dispose();

            return image;
        }

        public static bool CompareBitmapsFast(Bitmap bmp1, Bitmap bmp2)
        {
            if (bmp1 == null || bmp2 == null)
                return false;
            if (object.Equals(bmp1, bmp2))
                return true;
            if (!bmp1.Size.Equals(bmp2.Size) || !bmp1.PixelFormat.Equals(bmp2.PixelFormat))
                return false;

            int bytes = bmp1.Width * bmp1.Height * (Image.GetPixelFormatSize(bmp1.PixelFormat) / 8);

            bool result = true;
            byte[] b1bytes = new byte[bytes];
            byte[] b2bytes = new byte[bytes];

            BitmapData bitmapData1 = bmp1.LockBits(new Rectangle(0, 0, bmp1.Width, bmp1.Height), ImageLockMode.ReadOnly, bmp1.PixelFormat);
            BitmapData bitmapData2 = bmp2.LockBits(new Rectangle(0, 0, bmp2.Width, bmp2.Height), ImageLockMode.ReadOnly, bmp2.PixelFormat);

            Marshal.Copy(bitmapData1.Scan0, b1bytes, 0, bytes);
            Marshal.Copy(bitmapData2.Scan0, b2bytes, 0, bytes);

            for (int n = 0; n <= bytes - 1; n++)
            {
                if (b1bytes[n] != b2bytes[n])
                {
                    result = false;
                    break;
                }
            }

            bmp1.UnlockBits(bitmapData1);
            bmp2.UnlockBits(bitmapData2);

            return result;
        }

        public static bool CompareBitmapsLazy(Bitmap bmp1, Bitmap bmp2)
        {
            if (bmp1 == null || bmp2 == null)
                return false;
            if (object.Equals(bmp1, bmp2))
                return true;
            if (!bmp1.Size.Equals(bmp2.Size) || !bmp1.PixelFormat.Equals(bmp2.PixelFormat))
                return false;

            //Compare bitmaps using GetPixel method
            for (int column = 0; column < bmp1.Width; column++)
            {
                for (int row = 0; row < bmp1.Height; row++)
                {
                    if (!bmp1.GetPixel(column, row).Equals(bmp2.GetPixel(column, row)))
                        return false;
                }
            }

            return true;
        }

        public static void saveFinalImage()
        {
            if (m_EncryptedImages != null)
            {
                Bitmap source = new Bitmap(m_EncryptedImages[0].Width, m_EncryptedImages[0].Height);
                Graphics g = Graphics.FromImage(source);
                Rectangle rect = new Rectangle(0, 0, 0, 0);
                for (int i = 0; i < m_EncryptedImages.Length; i++)
                {
                    rect.Size = m_EncryptedImages[i].Size;
                    g.DrawImage(m_EncryptedImages[i], rect);
                    rect.Y += m_EncryptedImages[i].Height + 5;
                }

                g.DrawLine(new Pen(new SolidBrush(Color.Black), 1), rect.Location, new Point(rect.Width, rect.Y));
                rect.Y += 5;

                for (int i = 0; i < m_EncryptedImages.Length; i++)
                {
                    rect.Size = m_EncryptedImages[i].Size;
                    g.DrawImage(m_EncryptedImages[i], rect);
                }

                Bitmap b = new Bitmap(m_EncryptedImages[0].Width, m_EncryptedImages[0].Height,g);
                b.Save(Path.Combine(HttpContext.Current.Server.MapPath("~/Images/" + "Test.bmp")));
                source.Save(Path.Combine(HttpContext.Current.Server.MapPath("~/Images/" + "BTest.bmp")));
            }
        }
    }
}