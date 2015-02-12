#include <string>
#include <sstream>
#include <fstream>
#include <memory>
#include <atomic>
#include <atscppapi/GlobalPlugin.h>
#include <atscppapi/TransactionPlugin.h>
#include <atscppapi/Logger.h>
#include <atscppapi/PluginInit.h>
#include <atscppapi/utils.h>
#include <jsoncpp/json/json.h>

#include "Blacklist.h"
#include "TransactionHolder.h"

using namespace atscppapi;
using namespace TrafficGuard;
using std::string;
using std::ostringstream;
using std::shared_ptr;
using std::make_shared;
using std::atomic;
using std::ifstream;

namespace TrafficGuard {
  Logger tg_log;
  Json::Value config_root;
}

class TrafficGuardTransactionPlugin : public TransactionPlugin
{
public:
  TrafficGuardTransactionPlugin (Transaction &transaction,
                                 string landingpage, string category)
    : TransactionPlugin (transaction), location_ (landingpage),
      category_ (category)
  {
    TransactionPlugin::registerHook (HOOK_SEND_RESPONSE_HEADERS);
    transaction.error ();
  }

  void handleSendResponseHeaders (Transaction &transaction);

private:
  string location_;
  string category_;
  shared_ptr<TransactionHolder> transaction_holder_;
};

void
TrafficGuardTransactionPlugin::handleSendResponseHeaders (Transaction &transaction)
{
  tg_log.logInfo ("Request: %s %s [Category: %s]",
    utils::getIpString (transaction.getClientAddress ()).c_str (),
    transaction.getClientRequest ().getUrl ().getUrlString ().c_str (),
    category_.c_str ());

  transaction.getClientResponse ().setStatusCode (HTTP_STATUS_MOVED_TEMPORARILY);
  transaction.getClientResponse ().setReasonPhrase ("Moved Temporarily");

  ostringstream full_location;
  full_location << location_ << "?cat=" << category_
    << "&origin=" << transaction.getClientRequest ().getUrl ().getUrlString ();


  transaction.getClientResponse ().getHeaders ()["Location"] = full_location.str ();
  transaction.resume ();
}

class TransactionStatePlugin : public TransactionPlugin
{
public:
  TransactionStatePlugin (Transaction &transaction,
                          shared_ptr<TransactionHolder> holder)
    : TransactionPlugin (transaction), transaction_holder_ (holder) {}

  ~TransactionStatePlugin ()
  {
    transaction_holder_->destroy ();
  }

private:
  shared_ptr<TransactionHolder> transaction_holder_;
};

class TrafficGuardGlobalPlugin : public GlobalPlugin
{
public:
  TrafficGuardGlobalPlugin ()
    : blacklist_ (NULL),
      base_path_ ("/etc/trafficguard/blacklists"),
      ready_ (false)
  {
    blacklist_ = make_shared<Blacklist> (base_path_, &ready_,
                                         config_root["Workers"].asInt ());
    registerHook (HOOK_SEND_REQUEST_HEADERS);
  }

  void handleSendRequestHeaders (Transaction &transaction);

private:
  shared_ptr<Blacklist> blacklist_;
  string       base_path_;
  atomic<bool> ready_;
};

void
TrafficGuardGlobalPlugin::handleSendRequestHeaders (Transaction &transaction)
{
  if (ready_)
    {
      auto cb = [] (shared_ptr<TransactionHolder> transaction_holder,
                    string blacklist_category)
      {
        shared_ptr<TransactionHolder> holder (transaction_holder);
        if (!holder->isDestroy ())
          {
            Transaction *transaction = holder->getTransaction ();

            if (blacklist_category.length () == 0)
              {
                transaction->resume ();
                return;
              }

            transaction->addPlugin (new TrafficGuardTransactionPlugin (
                                      *transaction,
                                      config_root["LandingPage"].asString (),
                                      blacklist_category));
          }
      };

      shared_ptr<TransactionHolder> transaction_holder (new TransactionHolder (transaction, cb));
      transaction.addPlugin (new TransactionStatePlugin (transaction, transaction_holder));

      if (!blacklist_->MatchQueueAdd (transaction_holder))
        {
          transaction.resume ();
        }
    }
  else
    {
      transaction.resume ();
    }
}

static bool
readConfig_ () {
  ifstream conf ("/etc/trafficguard/tg.conf");
  Json::Reader reader;

  bool success = reader.parse (conf, config_root);
  if (!success)
    {
      tg_log.logInfo ("TrafficGuard config failed");
      return false;
    }

  tg_log.logInfo ("TrafficGuard config");
  tg_log.logInfo ("  -- LandingPage = %s",
                  config_root["LandingPage"].asString ().c_str ());
  tg_log.logInfo ("  -- Workers     = %d",
                  config_root["Workers"].asInt () < 1 ? 1 :
                    config_root["Workers"].asInt ());

  return true;
}

void
TSPluginInit (int argc ATSCPPAPI_UNUSED, const char *argv[] ATSCPPAPI_UNUSED)
{
  tg_log.init ("trafficguard", true, true, Logger::LOG_LEVEL_DEBUG, false, 0);

  tg_log.logInfo ("TrafficGuard starting");

  if (readConfig_ ())
    {
      new TrafficGuardGlobalPlugin ();
    }
}
