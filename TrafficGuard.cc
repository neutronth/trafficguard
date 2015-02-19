#include <string>
#include <sstream>
#include <fstream>
#include <memory>
#include <atomic>
#include <unordered_map>
#include <atscppapi/GlobalPlugin.h>
#include <atscppapi/TransactionPlugin.h>
#include <atscppapi/InterceptPlugin.h>
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
using std::unordered_map;

namespace TrafficGuard {
  Logger tg_log;
  Json::Value config_root;
}

class TrafficGuardTransactionPlugin : public TransactionPlugin
{
public:
  TrafficGuardTransactionPlugin (Transaction &transaction,
                                 shared_ptr<Blacklist> blacklist,
                                 string landingpage)
    : TransactionPlugin (transaction), blacklist_ (blacklist),
      location_ (landingpage)
  {
    auto cb = [this] (shared_ptr<TransactionHolder> transaction_holder,
                      string blacklist_category)
    {
      Transaction *transaction = transaction_holder->getTransaction ();

      if (blacklist_category.length () == 0)
        {
          transaction->resume ();
          return;
        }

      category_ = blacklist_category;
      TransactionPlugin::registerHook (HOOK_SEND_RESPONSE_HEADERS);
      transaction->error ();
    };

    transaction_holder_ = shared_ptr<TransactionHolder>(new TransactionHolder (transaction, getMutex (), cb));

    if (!blacklist_->MatchQueueAdd (transaction_holder_))
      {
        transaction.resume ();
      }
  }

  ~TrafficGuardTransactionPlugin ()
  {
    transaction_holder_->setTransactionDestroyed ();
  }

  void handleSendResponseHeaders (Transaction &transaction);

private:
  shared_ptr<Blacklist> blacklist_;
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

class TrafficGuardPatternsReloadIntercept : public InterceptPlugin
{
public:
  TrafficGuardPatternsReloadIntercept (Transaction &transaction) :
    InterceptPlugin (transaction, InterceptPlugin::TRANSACTION_INTERCEPT) {}

  void consume (const string &data, InterceptPlugin::RequestDataType type);
  void handleInputComplete ();

  ~TrafficGuardPatternsReloadIntercept () {}
};

void
TrafficGuardPatternsReloadIntercept::consume (
  const string &data ATSCPPAPI_UNUSED,
  InterceptPlugin::RequestDataType type ATSCPPAPI_UNUSED)
{
  /* Do nothing */
}

void
TrafficGuardPatternsReloadIntercept::handleInputComplete ()
{
  string response("HTTP/1.1 200 OK\r\n"
                  "\r\n");
  InterceptPlugin::produce(response);
  InterceptPlugin::setOutputComplete();
}

class TrafficGuardGlobalPlugin : public GlobalPlugin
{
public:
  TrafficGuardGlobalPlugin ()
    : GlobalPlugin (true),
      blacklist_ (NULL), base_path_ ("/etc/trafficguard/blacklists"),
      ready_ (false)
  {
    blacklist_ = make_shared<Blacklist> (base_path_, &ready_,
                                         config_root["Workers"].asInt ());
    registerHook (HOOK_READ_REQUEST_HEADERS_PRE_REMAP);
    registerHook (HOOK_SEND_REQUEST_HEADERS);
  }

  void handleReadRequestHeadersPreRemap (Transaction &transaction);
  void handleSendRequestHeaders (Transaction &transaction);

private:
  shared_ptr<Blacklist> blacklist_;
  string       base_path_;
  atomic<bool> ready_;
};

void
TrafficGuardGlobalPlugin::handleReadRequestHeadersPreRemap (Transaction &transaction)
{

  if (transaction.getClientRequest ().getMethod () == HTTP_METHOD_PURGE)
    {
      string clientip = utils::getIpString (transaction.getClientAddress ());
      if (clientip != "127.0.0.1")
        {
          transaction.resume ();
          return;
        }

      string url = transaction.getClientRequest ().getUrl ().getUrlString ();
      if (url.find ("/trafficguard/patterns") != std::string::npos)
        {
          tg_log.logInfo ("Reload patterns...");
          blacklist_->LoadPatterns ();
          transaction.addPlugin (new TrafficGuardPatternsReloadIntercept (transaction));
        }
    }

  transaction.resume ();
}

void
TrafficGuardGlobalPlugin::handleSendRequestHeaders (Transaction &transaction)
{
  if (ready_)
    {
      transaction.addPlugin (new TrafficGuardTransactionPlugin (
                               transaction, blacklist_,
                               config_root["LandingPage"].asString ()));
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

  if (readConfig_ ())
    {
      unordered_map<string, function<Logger::LogLevel ()>> loglevel_map;

      loglevel_map["nolog"] = [] () { return Logger::LOG_LEVEL_NO_LOG; };
      loglevel_map["error"] = [] () { return Logger::LOG_LEVEL_ERROR;  };
      loglevel_map["info"]  = [] () { return Logger::LOG_LEVEL_INFO;   };
      loglevel_map["debug"] = [] () { return Logger::LOG_LEVEL_DEBUG;  };

      auto loglevel_get = loglevel_map[config_root["LogLevel"].asString ()];
      auto loglevel = loglevel_get ? loglevel_get () : loglevel_map["info"] ();

      tg_log.init ("trafficguard", true, true, loglevel, false, 0);
      tg_log.logInfo ("TrafficGuard starting");

      new TrafficGuardGlobalPlugin ();
    }
}
