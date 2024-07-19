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
	/**响应服务器返回数据事件处理
	*
	* 继承 IEventCommProxyData
	*/
	virtual void OnNewDataArrived(protocol::message::TMessageForRecvPtr data);

	/**连接成功事件处理
	*
	* 继承 IEventCommProxyCtrl
	*/
	virtual void OnConnected(commproxy::ICommProxyCtrl* sender,TParamOnConnected* para);
	/**异常断线事件处理
	*
	* 继承 IEventCommProxyCtrl
	*/
	virtual void OnDisconnected(commproxy::ICommProxyCtrl* sender,TParamOnDisconnected* para);
	/**连接超时事件处理
	*
	* 继承 IEventCommProxyCtrl
	*/
	virtual void OnConnecteTimedout(commproxy::ICommProxyCtrl* sender,TParamOnConnecteTimedout* para);

	/**设置登录信息
	*
	* 继承 ILogin
	* @param[in] para 参数
	*/
	virtual void SetLoginInfo(const TLoginInfo& para);

	/**获取当前的登录信息
	*
	* 继承 ILogin
	* @return 登录信息引用
	*/
	virtual const TLoginInfo& GetLoginInfo();
	virtual void AppendInfo(calmstreet::uint16_t sUserType, std::string strUserValue){}
	virtual void RegisterTradeService(){};

	/**发起登录（异步）
	*
	* 继承 ILogin
	*/
	virtual void Login();
	/**发起注销（异步）
	*
	* 继承 ILogin
	*/
	virtual void Logoff();
	/**获取当前的登录状态
	* 
	* 继承 ILogin
	* @return 登录状态引用
	*/
	virtual const TStatusLogin& GetStatus() const;
	/**注册登录事件回调
	* 
	* 继承 ILogin
	*  @param[in] callback 事件回调接口
	*/
	virtual void Regist(IEventLogin *callback);
	virtual void Regist(ITradeEventLogin* callback);
	virtual void Regist(IEventLoginTradeProxy* callback);
	/**注销登录事件回调
	* 
	* 继承 ILogin
	*  @param[in] callback 事件回调接口
	*/
	virtual void Unregist(IEventLogin *callback);
	virtual void Unregist(ITradeEventLogin* callback);
	virtual void Unregist(IEventLoginTradeProxy* callback);
	/**获取用户ID，只有登录成功后才有效
	* 
	* 继承 ILogin
	*  @return 用户ID(服务器返回的)
	*/
    virtual calmstreet::uint32_t GetUserID() const;

	/**时钟事件处理
	* 
	* 继承 ILogin
	*  @param[in] id 时钟ID
	*/
	virtual void OnTimer(timer::TTimerID id);

	/*获取注册状态
	*
	*/
	TRegStatus GetRegStatus(){ return eNotRegistered; }

	virtual void SendClientInfo(){};

public:
	/**构造函数
	*/
	CLoginBase();
	/**析构函数
	*/
	virtual ~CLoginBase();
	/**设置通讯代理控制接口
	* 
	*  @param[in] comm_ctrl 通讯代理控制接口
	*/
	void SetCommProxyCtrl(commproxy::ICommProxyCtrl* comm_ctrl);
	/**设置通讯代理数据接口
	* 
	*  @param[in] comm_data 通讯代理数据接口
	*/
	void SetCommProxyData(commproxy::ICommProxyData* comm_data);
	/**设置时钟管理接口
	* 
	*  @param[in] timer_manager 时钟管理接口
	*/
	void SetTimerManager(timer::ITimerManager* timer_manager);
};

}}}}


#endif // __CALMSTREET_NT_CORE_SESSION__LOGINBASE_H__