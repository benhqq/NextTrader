#ifndef __CALMSTREET_NT_CORE_SESSION__LOGINBASE_H__
#define __CALMSTREET_NT_CORE_SESSION__LOGINBASE_H__

#include <calmstreet/type_def.h>
#include <calmstreet/i_timer.h>
#include <core/module_base.h>
#include <core/comm_proxy/i_comm_proxy_ctrl.h>
#include <core/comm_proxy/i_comm_proxy_data.h>
#include <core/session/i_login.h>

namespace calmstreet{
namespace nt{
namespace core{
namespace session{

typedef struct _Workflow
{
	typedef enum
	{
		UNKNOW
		,SOCKET_CONNECTING
		,SOCKET_CONNECT_TIMEDOUT
		,SOCKET_CONNECTED

		,KEY_CHALLENGES_REQ
		,RET_KEY_CHALLENGES_BAD
		,RET_KEY_CHALLENGES_OK

		,LOGIN_REQ
		,LOGIN_OK
		,LOGIN_BAD

		,LOGOFF_REQ
		,LOGOFF_OK
		,LOGOFF_BAD
	}TEnumWorkflow;

	TEnumWorkflow value;
	_Workflow():value(UNKNOW){}
	_Workflow(const TEnumWorkflow val):value(val){}
	_Workflow(const _Workflow& rhs){value = rhs.value;}
	const _Workflow& operator=(const _Workflow& rhs) {value = rhs.value;return (*this);}
	const _Workflow& operator=(const TEnumWorkflow val){value = val;return (*this);}
	void Reset(){value = UNKNOW;}
}TLoginWorkflow;

inline bool operator==(const TLoginWorkflow& a, const TLoginWorkflow& b)
{
	bool ret = (a.value != TLoginWorkflow::UNKNOW 
		&& b.value != TLoginWorkflow::UNKNOW
		&& a.value == b.value);

	return ret;
}

inline bool operator==(const TLoginWorkflow& a, const TLoginWorkflow::TEnumWorkflow b){return (a.value==b);}
inline bool operator==(const TLoginWorkflow::TEnumWorkflow a, const TLoginWorkflow& b){return (a==b.value);}

class CLoginBase
	: public CModuleBase
	, public ILogin
	, public commproxy::IEventCommProxyCtrl
	, public commproxy::IEventCommProxyData
	, public timer::IEventTimer
{
public:
	typedef std::vector<IEventLogin*> TEventLoginCallBack;
	typedef std::vector<ITradeEventLogin*> TTradeEventLoginCallBack;
	typedef std::vector<IEventLoginTradeProxy*> TTradeEventLoginProxyCallBack;

protected:
	TEventLoginCallBack m_EventLoginCallBack;
	TTradeEventLoginCallBack m_TradeEventLoginCallBack;
	TTradeEventLoginProxyCallBack m_TradeEventLoginProxyCallBack;
	TLoginInfo m_LoginInfo;
	commproxy::ICommProxyCtrl* m_CommProxyCtrl;
	commproxy::ICommProxyData* m_CommProxyData;
	TLoginWorkflow m_Workflow;
	TStatusLogin m_Status;
	timer::ITimerManager* m_ITimerManager;
	timer::TTimerID m_LoginTimer;
	timer::TTimerID m_LogOffTimer;
	protocol::message::CErrorCode m_ErrorCode;
	std::string m_strLoginKey;
	calmstreet::uint32_t m_nPassportUserId; 

	bool	m_bIsPublicAccount;

protected:
	void _StartLoginTimer();
	void _StopLoginTimer();
	void _StartLogoffTimer();
	void _StopLogoffTimer();

protected:
	virtual bool IsPublicAccount();
	virtual void SendKeyChallengesRequest(){}
	virtual void DisposeKeyChallengesResponse(protocol::message::TMessageForRecvPtr data){}
	virtual void DisposeInfoResponse(protocol::message::TMessageForRecvPtr data){}
	virtual void DisposeRegisterTradeServiceResponse(protocol::message::TMessageForRecvPtr data){}
	virtual void DisposeLogoffResponse(protocol::message::TMessageForRecvPtr data){}
	virtual void DisposeLoginResponse(protocol::message::TMessageForRecvPtr data){}
	virtual void DisposeTokenResponse(protocol::message::TMessageForRecvPtr data){}
	virtual void DisposeKickoffResponse(protocol::message::TMessageForRecvPtr data);
	virtual void OnClientInfoNotify(calmstreet::uint32_t RetCode, calmstreet::uint32_t RetId, std::string RetMsg){}
	virtual void SendTokenRequest(){}
	virtual void SendLogoffRequest(){}
	virtual void NotifyLoginOK(){}
	virtual void NotifyLoginFails(){}
	virtual void NotifyLginTimedout(){}

	virtual void NotifyLogining(){}
	virtual void NotifyLogoff(TParamEventLogoff& para){}
	virtual void NotifyKickoff(){}

public:
	/**��Ӧ���������������¼�����
	*
	* �̳� IEventCommProxyData
	*/
	virtual void OnNewDataArrived(protocol::message::TMessageForRecvPtr data);

	/**���ӳɹ��¼�����
	*
	* �̳� IEventCommProxyCtrl
	*/
	virtual void OnConnected(commproxy::ICommProxyCtrl* sender,TParamOnConnected* para);
	/**�쳣�����¼�����
	*
	* �̳� IEventCommProxyCtrl
	*/
	virtual void OnDisconnected(commproxy::ICommProxyCtrl* sender,TParamOnDisconnected* para);
	/**���ӳ�ʱ�¼�����
	*
	* �̳� IEventCommProxyCtrl
	*/
	virtual void OnConnecteTimedout(commproxy::ICommProxyCtrl* sender,TParamOnConnecteTimedout* para);

	/**���õ�¼��Ϣ
	*
	* �̳� ILogin
	* @param[in] para ����
	*/
	virtual void SetLoginInfo(const TLoginInfo& para);

	/**��ȡ��ǰ�ĵ�¼��Ϣ
	*
	* �̳� ILogin
	* @return ��¼��Ϣ����
	*/
	virtual const TLoginInfo& GetLoginInfo();
	virtual void AppendInfo(calmstreet::uint16_t sUserType, std::string strUserValue){}
	virtual void RegisterTradeService(){};

	/**�����¼���첽��
	*
	* �̳� ILogin
	*/
	virtual void Login();
	/**����ע�����첽��
	*
	* �̳� ILogin
	*/
	virtual void Logoff();
	/**��ȡ��ǰ�ĵ�¼״̬
	* 
	* �̳� ILogin
	* @return ��¼״̬����
	*/
	virtual const TStatusLogin& GetStatus() const;
	/**ע���¼�¼��ص�
	* 
	* �̳� ILogin
	*  @param[in] callback �¼��ص��ӿ�
	*/
	virtual void Regist(IEventLogin *callback);
	virtual void Regist(ITradeEventLogin* callback);
	virtual void Regist(IEventLoginTradeProxy* callback);
	/**ע����¼�¼��ص�
	* 
	* �̳� ILogin
	*  @param[in] callback �¼��ص��ӿ�
	*/
	virtual void Unregist(IEventLogin *callback);
	virtual void Unregist(ITradeEventLogin* callback);
	virtual void Unregist(IEventLoginTradeProxy* callback);
	/**��ȡ�û�ID��ֻ�е�¼�ɹ������Ч
	* 
	* �̳� ILogin
	*  @return �û�ID(���������ص�)
	*/
    virtual calmstreet::uint32_t GetUserID() const;

	/**ʱ���¼�����
	* 
	* �̳� ILogin
	*  @param[in] id ʱ��ID
	*/
	virtual void OnTimer(timer::TTimerID id);

	/*��ȡע��״̬
	*
	*/
	TRegStatus GetRegStatus(){ return eNotRegistered; }

	virtual void SendClientInfo(){};

public:
	/**���캯��
	*/
	CLoginBase();
	/**��������
	*/
	virtual ~CLoginBase();
	/**����ͨѶ������ƽӿ�
	* 
	*  @param[in] comm_ctrl ͨѶ������ƽӿ�
	*/
	void SetCommProxyCtrl(commproxy::ICommProxyCtrl* comm_ctrl);
	/**����ͨѶ�������ݽӿ�
	* 
	*  @param[in] comm_data ͨѶ�������ݽӿ�
	*/
	void SetCommProxyData(commproxy::ICommProxyData* comm_data);
	/**����ʱ�ӹ���ӿ�
	* 
	*  @param[in] timer_manager ʱ�ӹ���ӿ�
	*/
	void SetTimerManager(timer::ITimerManager* timer_manager);
};

}}}}


#endif // __CALMSTREET_NT_CORE_SESSION__LOGINBASE_H__