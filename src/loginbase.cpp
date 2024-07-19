#include "LoginBase.h"
#include <core/session/login.h>
#include <core/protocol/message/error_code.h>

namespace calmstreet{
namespace nt{
namespace core{
namespace session{

CLoginBase::CLoginBase()
	:CModuleBase()
	,m_EventLoginCallBack()
	,m_TradeEventLoginCallBack()
	,m_TradeEventLoginProxyCallBack()
	,m_LoginInfo()	
	,m_CommProxyCtrl(NULL)	
	,m_CommProxyData(NULL)
	,m_Status(TStatusLogin::LOGOFF)
	,m_Workflow()
	,m_ITimerManager(NULL)
	,m_LoginTimer()	
	,m_LogOffTimer()
	,m_ErrorCode()
	,m_bIsPublicAccount(false)
{
}

CLoginBase::~CLoginBase()
{
	if (m_ITimerManager!=NULL)
	{
		m_ITimerManager->ReleaseTimer(m_LoginTimer);
	}
}

void CLoginBase::SetLoginInfo(const TLoginInfo& para)
{
	m_LoginInfo = para;
}

const TLoginInfo& CLoginBase::GetLoginInfo()
{
	return m_LoginInfo;
}

void CLoginBase::SetCommProxyCtrl(commproxy::ICommProxyCtrl* comm_ctrl)
{
	if (NULL != m_CommProxyCtrl)
	{
		m_CommProxyCtrl->UnRegist(this);
	}

	m_CommProxyCtrl = comm_ctrl;
	m_CommProxyCtrl->Regist(this);
}

void CLoginBase::SetCommProxyData(commproxy::ICommProxyData* comm_data)
{
	if (NULL != m_CommProxyData)
	{
		m_CommProxyData->Unregist(this);
	}

	m_CommProxyData = comm_data;
	m_CommProxyData->Regist(this);
}

void CLoginBase::Login()
{
	if (TStatusLogin::LOGINING == m_Status || TStatusLogin::LOGINED == m_Status)
	{
		return ;
	}

	_StartLoginTimer();
	m_Workflow.Reset();
	m_Workflow = TLoginWorkflow::SOCKET_CONNECTING;
	m_Status = TStatusLogin::LOGINING;
	m_CommProxyCtrl->Connect(m_LoginInfo.login_timedout_sec,m_LoginInfo.remote_ip,m_LoginInfo.remote_port);
	NotifyLogining();
}

void CLoginBase::OnConnected(commproxy::ICommProxyCtrl* sender,TParamOnConnected* para)
{
	assert(TLoginWorkflow::SOCKET_CONNECTING == m_Workflow);
	assert(TStatusLogin::LOGINING == m_Status);

	m_Workflow = TLoginWorkflow::SOCKET_CONNECTED;
	SendClientInfo();
	SendKeyChallengesRequest();//已连接，发送挑战	
}

void CLoginBase::OnDisconnected(commproxy::ICommProxyCtrl* sender,TParamOnDisconnected* para)
{
	_StopLoginTimer();
	_StopLogoffTimer();

	if (TStatusLogin::LOGINED == m_Status)
	{
		m_Status = TStatusLogin::LOGOFF;

		TParamEventLogoff para;
		para.remote_ip = m_LoginInfo.remote_ip;
		para.remote_port = m_LoginInfo.remote_port;
		para.is_except_disconnect = true;
		NotifyLogoff(para);
		return;
	}

	if (TStatusLogin::LOGINING == m_Status)
	{
		m_Status = TStatusLogin::LOGOFF;

		TParamEventLogoff para;
		para.remote_ip  = m_LoginInfo.remote_ip;
		para.remote_port = m_LoginInfo.remote_port;
		para.is_except_disconnect = true;
		NotifyLogoff(para);
		return;
	}

	if (TStatusLogin::LOGOFFING == m_Status)
	{
		m_Status = TStatusLogin::LOGOFF;

		TParamEventLogoff para;
		para.remote_ip = m_LoginInfo.remote_ip;
		para.remote_port = m_LoginInfo.remote_port;
		para.is_except_disconnect = false;
		NotifyLogoff(para);
		return;
	}
	//assert(false);
}

void CLoginBase::OnConnecteTimedout(commproxy::ICommProxyCtrl* sender,TParamOnConnecteTimedout* para)
{
	_StopLoginTimer();
	m_Workflow.Reset();
	m_Status = TStatusLogin::LOGOFF;
	NotifyLginTimedout();
}

void CLoginBase::Logoff()
{
	if (!(TLoginWorkflow::LOGIN_OK == m_Workflow || TStatusLogin::LOGINED == m_Status.value))
	{
		return;
	}

	//发送登出请求包
	SendLogoffRequest();

	m_Workflow = TLoginWorkflow::LOGOFF_REQ ;
	m_Status = TStatusLogin::LOGOFFING;
}

void CLoginBase::SetTimerManager(timer::ITimerManager* timer_manager)
{
	m_ITimerManager = timer_manager;
}

void CLoginBase::OnTimer(timer::TTimerID id)
{
	if (m_LoginTimer == id)
	{
		m_ITimerManager->ReleaseTimer(m_LoginTimer);
		m_LoginTimer.Clear();
		m_CommProxyCtrl->Disconnect();
		m_Workflow.Reset();
		m_Status = TStatusLogin::LOGOFF;		
		NotifyLginTimedout();
	}
	else if (m_LogOffTimer == id)
	{
		m_ITimerManager->ReleaseTimer(m_LogOffTimer);
		m_LogOffTimer.Clear();
		m_CommProxyCtrl->Disconnect();
		m_Workflow.Reset();
		m_Status = TStatusLogin::LOGOFF;		

		TParamEventLogoff para;
		para.is_except_disconnect = false;
		para.remote_ip = m_LoginInfo.remote_ip;
		para.remote_port = m_LoginInfo.remote_port;
		NotifyLogoff(para);
	}
	else
	{
		throw("OnTimer...... BAD timer id.");
	}
}

void CLoginBase::_StartLoginTimer()
{
	if (!m_ITimerManager->HasTimer(m_LoginTimer))
	{
		m_LoginTimer = m_ITimerManager->CreateTimer(this,m_LoginInfo.login_timedout_sec);
	}
}

void CLoginBase::_StopLoginTimer()
{
	m_ITimerManager->ReleaseTimer(m_LoginTimer);
	m_LoginTimer.Clear();
}

void CLoginBase::_StartLogoffTimer()
{
	if (!m_ITimerManager->HasTimer(m_LogOffTimer))
	{
		m_LogOffTimer = m_ITimerManager->CreateTimer(this,10);
	}
}

void CLoginBase::_StopLogoffTimer()
{
	m_ITimerManager->ReleaseTimer(m_LogOffTimer);
	m_LogOffTimer.Clear();
}

void CLoginBase::OnNewDataArrived(protocol::message::TMessageForRecvPtr data)
{
	//收到数据
	if (!data->IsFull())
	{
		return;
	}
	DisposeInfoResponse(data);
	DisposeKeyChallengesResponse(data);
	DisposeRegisterTradeServiceResponse(data);
	DisposeTokenResponse(data);
	DisposeLoginResponse(data);
	DisposeLogoffResponse(data);
	DisposeKickoffResponse(data);
}

void CLoginBase::DisposeKickoffResponse(protocol::message::TMessageForRecvPtr data)
{
	if (data->TID()!=220113)
	{
		return;
	}

	Logoff();
	NotifyKickoff();
}

const TStatusLogin& CLoginBase::GetStatus() const
{
	return m_Status;
}

void CLoginBase::Regist(IEventLogin *callback)
{
	TEventLoginCallBack::iterator it;
	for (it=m_EventLoginCallBack.begin(); it!=m_EventLoginCallBack.end(); it++)
	{
		if((*it)==callback)
			return ;
	}
	m_EventLoginCallBack.push_back(callback);
}

void CLoginBase::Unregist(IEventLogin *callback)
{
	TEventLoginCallBack::iterator it;
	for (it=m_EventLoginCallBack.begin(); it!=m_EventLoginCallBack.end(); it++)
	{
		if((*it)==callback)
		{
			m_EventLoginCallBack.erase(it);
			return ;
		}
	}
}

calmstreet::uint32_t CLoginBase::GetUserID() const
{
	return 0;
}

void CLoginBase::Regist(ITradeEventLogin *callback)
{
	TTradeEventLoginCallBack::iterator it;
	for (it=m_TradeEventLoginCallBack.begin(); it!=m_TradeEventLoginCallBack.end(); it++)
	{
		if((*it)==callback)
			return ;
	}
	m_TradeEventLoginCallBack.push_back(callback);
}

void CLoginBase::Unregist(ITradeEventLogin *callback)
{
	TTradeEventLoginCallBack::iterator it;
	for (it=m_TradeEventLoginCallBack.begin(); it!=m_TradeEventLoginCallBack.end(); it++)
	{
		if((*it)==callback)
		{
			m_TradeEventLoginCallBack.erase(it);
			return ;
		}
	}
}

void CLoginBase::Regist(IEventLoginTradeProxy* callback)
{
	TTradeEventLoginProxyCallBack::iterator it;
	for (it=m_TradeEventLoginProxyCallBack.begin(); it!=m_TradeEventLoginProxyCallBack.end(); it++)
	{
		if((*it)==callback)
			return ;
	}
	m_TradeEventLoginProxyCallBack.push_back(callback);
}

void CLoginBase::Unregist(IEventLoginTradeProxy* callback)
{
	TTradeEventLoginProxyCallBack::iterator it;
	for (it=m_TradeEventLoginProxyCallBack.begin(); it!=m_TradeEventLoginProxyCallBack.end(); it++)
	{
		if((*it)==callback)
		{
			m_TradeEventLoginProxyCallBack.erase(it);
			return ;
		}
	}
}

bool CLoginBase::IsPublicAccount()
{
	return m_bIsPublicAccount;
}

}}}}