// Decompiled with JetBrains decompiler
// Type: RamseyServer.ClientThread
// Assembly: RamseyClient, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: B6542AE6-11B2-4AFA-90AF-31E7E307FD49
// Compiler-generated code is shown

using System;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace RamseyServer
{
  internal class ClientThread
  {
    private string flag;
    public TcpClient sock;
    private Thread ramseyThread;
    private Thread flagThread;
    private Semaphore mainSemaphore;
    private Semaphore ramseySemaphore;
    private Semaphore flagSemaphore;
    private byte[] comm;

    public ClientThread(string flagString, TcpClient sock)
    {
      this.mainSemaphore = new Semaphore(0, 1);
      this.ramseySemaphore = new Semaphore(0, 1);
      this.flagSemaphore = new Semaphore(0, 1);
      this.comm = new byte[4096];
      base.\u002Ector();
      this.flag = flagString;
      this.sock = sock;
      // ISSUE: method pointer
      this.ramseyThread = new Thread(new ParameterizedThreadStart((object) null, __methodptr(ramseyThreadStart)));
      // ISSUE: method pointer
      this.flagThread = new Thread(new ParameterizedThreadStart((object) null, __methodptr(flagThreadStart)));
    }

    public static void ManageClient(object clientThreadObj)
    {
      ClientThread clientThread = (ClientThread) clientThreadObj;
      try
      {
        clientThread.Run(clientThread.sock.GetStream());
      }
      catch (Exception ex)
      {
      }
      clientThread.Cleanup();
    }

    public void Run(NetworkStream sock)
    {
      ClientThread.\u003C\u003Ec__DisplayClass10_0 cDisplayClass100;
      cDisplayClass100.sock = sock;
      this.ramseyThread.Start((object) this);
      this.flagThread.Start((object) this);
label_1:
      int num1;
      while (true)
      {
        string s = ClientThread.\u003CRun\u003Eg__readline\u007C10_0(ref cDisplayClass100);
        if (s.Length != 0)
        {
          switch (int.Parse(s))
          {
            case 1:
              ClientThread.\u003CRun\u003Eg__sendline\u007C10_1(ClientThread.\u003CRun\u003Eg__readline\u007C10_0(ref cDisplayClass100), ref cDisplayClass100);
              continue;
            case 2:
              int num2 = int.Parse(ClientThread.\u003CRun\u003Eg__readline\u007C10_0(ref cDisplayClass100));
              int num3 = int.Parse(ClientThread.\u003CRun\u003Eg__readline\u007C10_0(ref cDisplayClass100));
              int num4 = int.Parse(ClientThread.\u003CRun\u003Eg__readline\u007C10_0(ref cDisplayClass100));
              if (num2 >= 0 && num2 <= 100 && (num3 >= 5 && num3 <= 10) && num4 >= 0)
              {
                this.comm[0] = (byte) num2;
                this.comm[1] = (byte) num3;
                int num5 = (num2 * num2 - num2) / 2 / 8;
                for (int index = 0; index < num5; ++index)
                  this.comm[2 + index] = (byte) 0;
                for (int index = 0; index < num4; ++index)
                {
                  string[] strArray = ClientThread.\u003CRun\u003Eg__readline\u007C10_0(ref cDisplayClass100).Split((char[]) null);
                  if (strArray.Length != 2)
                    return;
                  int num6 = int.Parse(strArray[0]);
                  int num7 = int.Parse(strArray[1]);
                  if (num6 < 0 || num6 >= num2 || (num7 < 0 || num7 >= num2) || num6 == num7)
                    return;
                  int num8;
                  int num9;
                  if (num6 > num7)
                  {
                    num8 = num7;
                    num9 = num6;
                  }
                  else
                  {
                    num9 = num7;
                    num8 = num6;
                  }
                  int num10 = num8 * num2 + num9;
                  for (; num8 >= 0; --num8)
                    num10 -= num8 + 1;
                  this.comm[2 + num10 / 8] |= (byte) (1 << num10 % 8);
                }
                this.ramseySemaphore.Release();
                this.mainSemaphore.WaitOne();
                if (this.comm[0] == (byte) 0 && this.comm[1] == (byte) 0 && (this.comm[2] == (byte) 0 && this.comm[3] == (byte) 0))
                {
                  ClientThread.\u003CRun\u003Eg__sendline\u007C10_1("Paul Erdos approves of this party!", ref cDisplayClass100);
                  continue;
                }
                ClientThread.\u003CRun\u003Eg__sendline\u007C10_1("Paul Erdos does not approve of this party...", ref cDisplayClass100);
                continue;
              }
              goto label_4;
            case 3:
              num1 = int.Parse(ClientThread.\u003CRun\u003Eg__readline\u007C10_0(ref cDisplayClass100));
              if (num1 >= 0 && num1 <= 100)
              {
                this.comm[0] = (byte) num1;
                int index1 = 1;
                for (int index2 = 0; index2 < num1 && index1 < 4096; ++index2)
                {
                  string str = ClientThread.\u003CRun\u003Eg__readline\u007C10_0(ref cDisplayClass100);
                  for (int index3 = 0; index3 < str.Length && index1 < 4096; ++index1)
                  {
                    this.comm[index1] = (byte) str[index3];
                    ++index3;
                  }
                  if (index1 < 4096)
                  {
                    this.comm[index1] = (byte) 0;
                    ++index1;
                  }
                }
                if (index1 >= 4096)
                {
                  ClientThread.\u003CRun\u003Eg__sendline\u007C10_1("Your flags are too large!", ref cDisplayClass100);
                  continue;
                }
                goto label_38;
              }
              else
                goto label_15;
            default:
              goto label_2;
          }
        }
        else
          break;
      }
      return;
label_2:
      return;
label_4:
      return;
label_15:
      return;
label_38:
      this.flagSemaphore.Release();
      this.mainSemaphore.WaitOne();
      for (int index = 0; index < num1; ++index)
      {
        if (this.comm[index * 4] == (byte) 0 && this.comm[1 + index * 4] == (byte) 0 && (this.comm[2 + index * 4] == (byte) 0 && this.comm[3 + index * 4] == (byte) 0))
          ClientThread.\u003CRun\u003Eg__sendline\u007C10_1("Correct!", ref cDisplayClass100);
        else
          ClientThread.\u003CRun\u003Eg__sendline\u007C10_1("Incorrect!", ref cDisplayClass100);
      }
      goto label_1;
    }

    public void Cleanup()
    {
      this.ramseyThread.Abort();
      this.flagThread.Abort();
      this.sock.Close();
    }

    private static void ramseyThreadStart(object self)
    {
      ((ClientThread) self).ramseyThreadMain();
    }

    private static void flagThreadStart(object self)
    {
      ((ClientThread) self).flagThreadMain();
    }

    private void ramseyThreadMain()
    {
      while (true)
      {
        this.ramseySemaphore.WaitOne();
        ClientThread.\u003C\u003Ec__DisplayClass14_0 cDisplayClass140;
        cDisplayClass140.gsize = (int) this.comm[0];
        int num1 = (int) this.comm[1];
        int num2 = 0;
        for (int node1 = 0; node1 < cDisplayClass140.gsize - num1 + 1; ++node1)
        {
          for (int index1 = node1 + 1; index1 < cDisplayClass140.gsize - num1 + 2; ++index1)
          {
            for (int index2 = index1 + 1; index2 < cDisplayClass140.gsize - num1 + 3; ++index2)
            {
              if (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index2, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index1, index2, ref cDisplayClass140))
              {
                for (int index3 = index2 + 1; index3 < cDisplayClass140.gsize - num1 + 4; ++index3)
                {
                  if (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index3, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index1, index3, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index2, index3, ref cDisplayClass140))
                  {
                    for (int index4 = index3 + 1; index4 < cDisplayClass140.gsize - num1 + 5; ++index4)
                    {
                      if (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index4, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index1, index4, ref cDisplayClass140) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index2, index4, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index3, index4, ref cDisplayClass140)))
                      {
                        if (num1 <= 5)
                        {
                          ++num2;
                        }
                        else
                        {
                          for (int index5 = index4 + 1; index5 < cDisplayClass140.gsize - num1 + 6; ++index5)
                          {
                            if (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index5, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index1, index5, ref cDisplayClass140) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index2, index5, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index3, index5, ref cDisplayClass140)) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index4, index5, ref cDisplayClass140))
                            {
                              if (num1 <= 6)
                              {
                                ++num2;
                              }
                              else
                              {
                                for (int index6 = index5 + 1; index6 < cDisplayClass140.gsize - num1 + 7; ++index6)
                                {
                                  if (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index6, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index1, index6, ref cDisplayClass140) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index2, index6, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index3, index6, ref cDisplayClass140)) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index4, index6, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index5, index6, ref cDisplayClass140)))
                                  {
                                    if (num1 <= 7)
                                    {
                                      ++num2;
                                    }
                                    else
                                    {
                                      for (int index7 = index6 + 1; index7 < cDisplayClass140.gsize - num1 + 8; ++index7)
                                      {
                                        if (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index7, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index1, index7, ref cDisplayClass140) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index2, index7, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index3, index7, ref cDisplayClass140)) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index4, index7, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index5, index7, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index6, index7, ref cDisplayClass140)))
                                        {
                                          if (num1 <= 8)
                                          {
                                            ++num2;
                                          }
                                          else
                                          {
                                            for (int index8 = index7 + 1; index8 < cDisplayClass140.gsize - num1 + 9; ++index8)
                                            {
                                              if (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index8, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index1, index8, ref cDisplayClass140) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index2, index8, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index3, index8, ref cDisplayClass140)) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index4, index8, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index5, index8, ref cDisplayClass140) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index6, index8, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index7, index8, ref cDisplayClass140))))
                                              {
                                                if (num1 <= 9)
                                                {
                                                  ++num2;
                                                }
                                                else
                                                {
                                                  for (int node2 = index8 + 1; node2 < cDisplayClass140.gsize - num1 + 10; ++node2)
                                                  {
                                                    if (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, node2, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index1, node2, ref cDisplayClass140) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index2, node2, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index3, node2, ref cDisplayClass140)) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index4, node2, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index5, node2, ref cDisplayClass140) && (this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index6, node2, ref cDisplayClass140) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index7, node2, ref cDisplayClass140))) && this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(node1, index1, ref cDisplayClass140) == this.\u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(index8, node2, ref cDisplayClass140))
                                                      ++num2;
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        this.comm[0] = (byte) (num2 & (int) byte.MaxValue);
        this.comm[1] = (byte) (num2 >> 8 & (int) byte.MaxValue);
        this.comm[2] = (byte) (num2 >> 16 & (int) byte.MaxValue);
        this.comm[3] = (byte) (num2 >> 24 & (int) byte.MaxValue);
        this.mainSemaphore.Release();
      }
    }

    private void flagThreadMain()
    {
      while (true)
      {
        this.flagSemaphore.WaitOne();
        int index1 = 1;
        int num1 = (int) this.comm[0];
        for (int index2 = 0; index2 < num1; ++index2)
        {
          string strB = "";
          for (; index1 < 4096 && this.comm[index1] != (byte) 0; ++index1)
            strB += ((char) this.comm[index1]).ToString();
          ++index1;
          int num2 = string.Compare(this.flag, strB, StringComparison.Ordinal);
          this.comm[4 * index2] = (byte) (num2 & (int) byte.MaxValue);
          this.comm[1 + 4 * index2] = (byte) (num2 >> 8 & (int) byte.MaxValue);
          this.comm[2 + 4 * index2] = (byte) (num2 >> 16 & (int) byte.MaxValue);
          this.comm[3 + 4 * index2] = (byte) (num2 >> 24 & (int) byte.MaxValue);
        }
        this.mainSemaphore.Release();
      }
    }

    [CompilerGenerated]
    internal static string \u003CRun\u003Eg__readline\u007C10_0([In] ref ClientThread.\u003C\u003Ec__DisplayClass10_0 obj0)
    {
      string str = "";
      while (true)
      {
        int num = obj0.sock.ReadByte();
        if (num != -1)
        {
          char ch = (char) num;
          if (ch != '\n')
            str += ch.ToString();
          else
            break;
        }
        else
          break;
      }
      return str;
    }

    [CompilerGenerated]
    internal static void \u003CRun\u003Eg__sendline\u007C10_1(string s, [In] ref ClientThread.\u003C\u003Ec__DisplayClass10_0 obj1)
    {
      for (int index = 0; index < s.Length; ++index)
      {
        char ch = s[index];
        obj1.sock.WriteByte((byte) ch);
      }
      obj1.sock.WriteByte((byte) 10);
    }

    [CompilerGenerated]
    private bool \u003CramseyThreadMain\u003Eg__areConnected\u007C14_0(int node1, int node2, [In] ref ClientThread.\u003C\u003Ec__DisplayClass14_0 obj2)
    {
      int num1;
      int num2;
      if (node1 > node2)
      {
        num1 = node1;
        num2 = node2;
      }
      else
      {
        num1 = node2;
        num2 = node1;
      }
      int num3 = num2 * obj2.gsize + num1;
      for (; num2 >= 0; --num2)
        num3 -= num2 + 1;
      return ((uint) this.comm[2 + num3 / 8] & (uint) (1 << num3 % 8)) > 0U;
    }

    [CompilerGenerated]
    [StructLayout(LayoutKind.Auto)]
    private struct \u003C\u003Ec__DisplayClass10_0
    {
      public NetworkStream sock;
    }

    [CompilerGenerated]
    [StructLayout(LayoutKind.Auto)]
    private struct \u003C\u003Ec__DisplayClass14_0
    {
      public int gsize;
    }
  }
}
