#ifndef FRAMEPACKET_H
#define FRAMEPACKET_H
#include<atlstr.h>

class FramePacket
{
public:
    FramePacket();
    virtual ~FramePacket();
        FramePacket(const unsigned char *buf,int buflen);
        void		GetMacSrcAddr(char *str);
        CString		GetMacSrcAddr();
        void		GetMacDestAddr(char *str);
        CString		GetMacDestAddr();
        int			GetType();
private:
    int m_nSrcAddr[6];   //源MAC地址
    int m_nDestAddr[6];  //目的MAC地址
    int m_nType;         //网络层报文类型:IP,ARP,RARP
};

#endif // FRAMEPACKET_H
