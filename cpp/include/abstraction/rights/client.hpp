#pragma once
#include <abstraction/rights/api/rec.h>
#include <abstraction/ipc/frame.hpp>
#include <algorithm>
namespace abstraction::rights {
inline void validate(const api::Decision& result){
 if(std::find(api::kDecisionOutcomeNames.begin(),api::kDecisionOutcomeNames.end(),result.outcome)==api::kDecisionOutcomeNames.end())throw api::ServiceError("invalid_response","unknown outcome");
 const bool evaluated=result.outcome=="permitted"||result.outcome=="denied"||result.outcome=="not_granted"||result.outcome=="unknown_action";
 if(evaluated!=!result.policy_revision.empty())throw api::ServiceError("invalid_decision","inconsistent policy revision");
}
class TrustedEnforcerClient;
class Client {
public:
 explicit Client(std::string endpoint):transport_(std::move(endpoint),5000,1u<<20){}
 Client(std::string endpoint,ipc::Deadline deadline):transport_(std::move(endpoint),deadline,1u<<20){}
 Client WithServerExpectation(std::optional<ipc::ServerExpectation> server) const {auto copy=*this;copy.transport_=transport_.WithServerExpectation(std::move(server));return copy;}
 Client WithCancellation(ipc::CancellationToken token)const{auto copy=*this;copy.transport_=transport_.WithCancellation(std::move(token));return copy;}
 api::Decision Decide(const std::string& action,const std::string& resource)const{
  auto transport=transport_;api::AuthorizationClient<ipc::FrameTransport> client(transport);auto result=client.Decide(action,resource);validate(result);return result;
 }
private:
 friend class TrustedEnforcerClient;
 ipc::FrameTransport transport_;
};
// Only a receiver-designated enforcement point may relay its bound subject.
// Constructing this adapter conveys no authority; the service checks each call.
class TrustedEnforcerClient {
public:
 explicit TrustedEnforcerClient(Client client):client_(std::move(client)){}
 api::Decision DecideFor(const api::Subject& subject,const std::string& action,const std::string& resource)const{
  auto transport=client_.transport_;api::AuthorizationClient<ipc::FrameTransport> client(transport);auto result=client.DecideFor(subject,action,resource);validate(result);return result;
 }
private: Client client_;
};
}
