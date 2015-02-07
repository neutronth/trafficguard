#ifndef _BLACKLIST_H
#define _BLACKLIST_H

#include <string>
#include <atomic>
#include <memory>
#include <vector>
#include <pcrecpp.h>
#include <atscppapi/Logger.h>

using namespace atscppapi;
using namespace pcrecpp;
using std::string;
using std::atomic;
using std::shared_ptr;
using std::vector;

namespace TrafficGuard
{

extern Logger tg_log;

class BlacklistCategory
{
public:
  BlacklistCategory (string name, string base_path);
  ~BlacklistCategory ();

  bool isValid () { return (domains_set_.size () > 0 || urls_set_.size () > 0); }
  string getName () { return name_; }

  bool DomainMatch (string text);
  bool UrlMatch    (string text);

private:
  bool Match (vector<shared_ptr<RE>> &storage, string text);
  void ProcessPatterns (string type, string &patterns);
  void StorePatterns   (string type, shared_ptr<RE> re);
  void LoadPatterns    (string type);
  void LoadDomains ();
  void LoadUrls ();

private:
  string     name_;
  string     base_path_;
  RE_Options pcre_opts_;
  vector<shared_ptr<RE>> domains_set_;
  vector<shared_ptr<RE>> urls_set_;
};

inline
BlacklistCategory::BlacklistCategory (string name, string base_path)
  : name_ (name), base_path_ (base_path)
{
  pcre_opts_.set_caseless (true)
    .set_utf8 (false)
    .set_extra (true)
    .set_multiline (false)
    .set_no_auto_capture (true);

  LoadDomains ();
  LoadUrls ();
}

inline
BlacklistCategory::~BlacklistCategory ()
{
  if (!isValid ())
    tg_log.logError ("Category: %s is invalid", name_.c_str ());

  tg_log.logDebug ("Category: %s destroyed", name_.c_str ());
}

class Blacklist
{
public:
  Blacklist (string base_path, atomic<bool> *ready);
  ~Blacklist ();

  void LoadPatterns ();
  bool Match (string domain, string url, string &ret_category);

private:
  void ReloadPatterns ();

private:
  string        base_path_;
  atomic<bool> *ready_;
  vector<shared_ptr<BlacklistCategory>> categories_;
};

inline
Blacklist::~Blacklist ()
{
  tg_log.logInfo ("Blacklist destroyed");
}

} /* TrafficGuard namespace */
#endif /* _BLACKLIST_H */